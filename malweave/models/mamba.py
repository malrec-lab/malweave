"""MIT-licensed bidirectional Mamba classifier port from RawByteClf's pinned implementation."""

from __future__ import annotations

from dataclasses import dataclass
import math

import torch
from torch import Tensor, nn
from torch.nn import functional as F
from torch.utils.checkpoint import checkpoint
from transformers.modeling_outputs import SequenceClassifierOutput
from transformers.models.mamba.modeling_mamba import MambaBlock, MambaRMSNorm


@dataclass
class MambaConfig:
    """RawByteClf MambaConfig fields consumed by the pinned transformer MambaBlock."""

    vocab_size: int
    hidden_size: int = 384
    num_hidden_layers: int = 32
    embedding_size: int | None = None
    state_size: int = 16
    layer_norm_epsilon: float = 1e-5
    pad_token_id: int = 0
    bos_token_id: int = 3
    eos_token_id: int = 4
    expand: int = 2
    conv_kernel: int = 4
    use_bias: bool = False
    use_conv_bias: bool = True
    hidden_act: str = "silu"
    residual_in_fp32: bool = True
    time_step_rank: int | str = "auto"
    hidden_dropout_prob: float = 0.0
    num_labels: int = 2
    is_decoder: bool = False
    bi_tie_directions: bool = False
    bi_mix_directions: bool = False
    bi_add_directions: bool = True
    use_mambapy: bool = False
    gradient_checkpointing: bool = False

    def __post_init__(self) -> None:
        if len({self.pad_token_id, self.bos_token_id, self.eos_token_id}) != 3:
            raise ValueError("Bidirectional Mamba requires distinct PAD, BOS, and EOS token IDs.")
        self.embedding_size = (
            self.hidden_size if self.embedding_size is None else self.embedding_size
        )
        self.intermediate_size = self.expand * self.hidden_size
        self.time_step_rank = (
            math.ceil(self.hidden_size / 16)
            if self.time_step_rank == "auto"
            else int(self.time_step_rank)
        )


class MambaForSequenceClassification(nn.Module):
    """Pinned bidirectional classifier: reverse input internally, combine final states without flip."""

    def __init__(self, config: MambaConfig) -> None:
        super().__init__()
        if config.is_decoder:
            raise ValueError(
                "This Mamba port is bidirectional; causal Mamba is a separate ablation."
            )
        self.config = config
        self.embeddings = nn.Embedding(
            config.vocab_size, config.embedding_size, config.pad_token_id
        )
        self.embedding_projection = (
            nn.Linear(config.embedding_size, config.hidden_size)
            if config.embedding_size != config.hidden_size
            else nn.Identity()
        )
        self.layers_forw = nn.ModuleList(
            [MambaBlock(config, layer_idx=index) for index in range(config.num_hidden_layers)]
        )
        self.layers_back = nn.ModuleList(
            [MambaBlock(config, layer_idx=index) for index in range(config.num_hidden_layers)]
        )
        self.norm_f = MambaRMSNorm(config.hidden_size, eps=config.layer_norm_epsilon)
        self.dropout = nn.Dropout(config.hidden_dropout_prob)
        self.classifier = nn.Linear(
            config.hidden_size if config.bi_add_directions else config.hidden_size * 2,
            config.num_labels,
        )
        if config.bi_tie_directions:
            self.tie_forward_and_backward_weights()

    def tie_forward_and_backward_weights(self) -> None:
        """Match RawByteClf's optional shared directional mixer projections."""
        for forward, backward in zip(self.layers_forw, self.layers_back, strict=True):
            for name in ("in_proj", "out_proj", "x_proj", "dt_proj"):
                source = getattr(forward.mixer, name)
                target = getattr(backward.mixer, name)
                target.weight = source.weight
                target.bias = source.bias

    def prepare_input_for_backward_model(self, input_ids: Tensor) -> Tensor:
        """Build `<BOS> + reversed content + <EOS> + PAD`, exactly as the upstream bidirectional path."""
        if input_ids.ndim != 2:
            raise ValueError("input_ids must have shape (batch, sequence).")
        reversed_ids = torch.zeros_like(input_ids)
        for batch_index, row in enumerate(input_ids):
            pads = torch.nonzero(row.eq(self.config.pad_token_id), as_tuple=False)
            pad_index = row.numel() if len(pads) == 0 else pads[0].item()
            content = row[1 : pad_index - 1].flip(0)
            rebuilt = torch.cat(
                [
                    torch.tensor([self.config.bos_token_id], dtype=row.dtype, device=row.device),
                    content,
                    torch.tensor([self.config.eos_token_id], dtype=row.dtype, device=row.device),
                ]
            )
            reversed_ids[batch_index, : rebuilt.numel()] = rebuilt
            if rebuilt.numel() < row.numel():
                reversed_ids[batch_index, rebuilt.numel() :] = self.config.pad_token_id
        return reversed_ids

    def _run_branch(self, input_ids: Tensor, layers: nn.ModuleList) -> Tensor:
        hidden = self.embedding_projection(self.dropout(self.embeddings(input_ids)))
        for layer in layers:
            if self.config.gradient_checkpointing and self.training:
                hidden = checkpoint(layer, hidden, use_reentrant=False)
            else:
                hidden = layer(hidden)
            hidden = self.dropout(hidden)
        return self.norm_f(hidden)

    def forward(
        self,
        input_ids: Tensor,
        attention_mask: Tensor | None = None,
        labels: Tensor | None = None,
    ) -> SequenceClassifierOutput:
        if attention_mask is not None:
            raise NotImplementedError(
                "Bidirectional Mamba does not implement attention_mask upstream."
            )
        backward_ids = self.prepare_input_for_backward_model(input_ids)
        forward_states = self._run_branch(input_ids, self.layers_forw)
        backward_states = self._run_branch(backward_ids, self.layers_back)
        # Classification intentionally does not flip the backward branch before combining it.
        hidden = (
            forward_states + backward_states
            if self.config.bi_add_directions
            else torch.cat([forward_states, backward_states], dim=-1)
        )
        token_logits = self.classifier(hidden)
        positions = input_ids.eq(self.config.pad_token_id).int().argmax(-1) - 1
        positions = positions.remainder(input_ids.shape[-1])
        logits = token_logits[torch.arange(input_ids.shape[0], device=input_ids.device), positions]
        loss = F.cross_entropy(logits, labels) if labels is not None else None
        return SequenceClassifierOutput(loss=loss, logits=logits)
