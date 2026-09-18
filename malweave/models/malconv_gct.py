"""MIT-licensed port of RawByteClf MalConvGCT at commit 2502450e40ac00363e168106662aac29821d4a93."""

from __future__ import annotations

from dataclasses import dataclass

import torch
from torch import Tensor, nn
from torch.nn import functional as F
from transformers.modeling_outputs import SequenceClassifierOutput


@dataclass(frozen=True)
class MalConvGCTConfig:
    """Pinned MalConvGCT architecture parameters for the RanDS RAW adaptation."""

    vocab_size: int = 257
    embedding_size: int = 8
    channels: int = 256
    stride: int = 64
    kernel_size: int = 256
    layers: int = 1
    pad_token_id: int = 0
    num_labels: int = 2
    chunk_size: int = 65_536
    min_chunk_size: int = 1_024


class _LowMemoryConvBase(nn.Module):
    """Faithful seq2fix scan/pool/recompute path used by both GCT branches."""

    def __init__(self, config: MalConvGCTConfig) -> None:
        super().__init__()
        self.chunk_size = config.chunk_size
        self.min_chunk_size = config.min_chunk_size
        self.pad_token_id = config.pad_token_id
        self.kernel_size = config.kernel_size
        self.stride = config.stride
        self.layers = config.layers
        self.pooling = nn.AdaptiveMaxPool1d(1)

    @property
    def receptive_field(self) -> int:
        return self.kernel_size + (self.layers - 1) * (self.kernel_size - 1)

    def process_range(self, input_ids: Tensor, **kwargs: Tensor) -> Tensor:
        raise NotImplementedError

    def seq2fix(self, input_ids: Tensor, **process_kwargs: Tensor) -> Tensor:
        """Select per-channel maxima from chunks, then recompute only their receptive windows."""
        receptive_field = self.receptive_field
        if input_ids.shape[1] < receptive_field:
            input_ids = F.pad(
                input_ids,
                (0, receptive_field - input_ids.shape[1]),
                value=self.pad_token_id,
            )
        batch_size, length = input_ids.shape
        device = self.embedding.weight.device
        winner_values: Tensor | None = None
        winner_indices: Tensor | None = None
        start = 0
        end = min(self.chunk_size, length)
        with torch.no_grad():
            while start < end and end - start >= max(self.min_chunk_size, receptive_field):
                activations = self.process_range(
                    input_ids[:, start:end].to(device), **process_kwargs
                )
                values, indices = F.max_pool1d(
                    activations, kernel_size=activations.shape[2], return_indices=True
                )
                values = values[..., 0]
                indices = indices[..., 0] * self.stride + start
                if winner_values is None:
                    winner_values = values
                    winner_indices = indices
                else:
                    selected = winner_values < values
                    winner_values = torch.where(selected, values, winner_values)
                    winner_indices = torch.where(selected, indices, winner_indices)
                start = end
                end = min(start + self.chunk_size, length)
        if winner_indices is None:
            raise RuntimeError("No chunk met MalConvGCT's minimum processable length.")
        selected_chunks: list[Tensor] = []
        for batch_index in range(batch_size):
            positions = torch.unique(winner_indices[batch_index]).tolist()
            windows = [
                input_ids[
                    batch_index,
                    max(position - receptive_field, 0) : min(position + receptive_field, length),
                ]
                for position in positions
            ]
            selected_chunks.append(torch.cat(windows))
        selected = nn.utils.rnn.pad_sequence(
            selected_chunks, batch_first=True, padding_value=self.pad_token_id
        ).to(device)
        pooled = self.pooling(self.process_range(selected, **process_kwargs))
        return pooled.reshape(batch_size, -1)


class _MalConvML(_LowMemoryConvBase):
    """Upstream MalConvML context branch, including its separate embedding table."""

    def __init__(self, config: MalConvGCTConfig, out_size: int) -> None:
        super().__init__(config)
        self.embedding = nn.Embedding(
            config.vocab_size, config.embedding_size, padding_idx=config.pad_token_id
        )
        self.convs = nn.ModuleList(
            [
                nn.Conv1d(
                    config.embedding_size,
                    config.channels * 2,
                    config.kernel_size,
                    stride=config.stride,
                    bias=True,
                )
            ]
            + [
                nn.Conv1d(
                    config.channels,
                    config.channels * 2,
                    config.kernel_size,
                    stride=1,
                    bias=True,
                )
                for _ in range(config.layers - 1)
            ]
        )
        self.convs_1 = nn.ModuleList(
            [
                nn.Conv1d(config.channels, config.channels, 1, bias=True)
                for _ in range(config.layers)
            ]
        )
        self.fc_1 = nn.Linear(config.channels, config.channels)
        self.fc_2 = nn.Linear(config.channels, out_size)

    def process_range(self, input_ids: Tensor, **_: Tensor) -> Tensor:
        hidden = self.embedding(input_ids).permute(0, 2, 1).contiguous()
        for conv_glu, conv_share in zip(self.convs, self.convs_1, strict=True):
            hidden = F.leaky_relu(conv_share(F.glu(conv_glu(hidden.contiguous()), dim=1)))
        return hidden

    def forward(self, input_ids: Tensor) -> tuple[Tensor, Tensor, Tensor]:
        post_conv = hidden = self.seq2fix(input_ids)
        penultimate = hidden = F.relu(self.fc_1(hidden))
        return self.fc_2(hidden), penultimate, post_conv


class _MalConvGCT(_LowMemoryConvBase):
    """Global-context-gated branch ported one operation at a time from RawByteClf."""

    def __init__(self, config: MalConvGCTConfig) -> None:
        super().__init__(config)
        self.embedding = nn.Embedding(
            config.vocab_size, config.embedding_size, padding_idx=config.pad_token_id
        )
        self.context_net = _MalConvML(config, out_size=config.channels)
        self.convs = nn.ModuleList(
            [
                nn.Conv1d(
                    config.embedding_size,
                    config.channels * 2,
                    config.kernel_size,
                    stride=config.stride,
                    bias=True,
                )
            ]
            + [
                nn.Conv1d(
                    config.channels,
                    config.channels * 2,
                    config.kernel_size,
                    stride=1,
                    bias=True,
                )
                for _ in range(config.layers - 1)
            ]
        )
        self.linear_atn = nn.ModuleList(
            [nn.Linear(config.channels, config.channels) for _ in range(config.layers)]
        )
        self.convs_share = nn.ModuleList(
            [
                nn.Conv1d(config.channels, config.channels, 1, bias=True)
                for _ in range(config.layers)
            ]
        )
        self.fc_1 = nn.Linear(config.channels, config.channels)
        self.fc_2 = nn.Linear(config.channels, config.num_labels)

    def process_range(self, input_ids: Tensor, **kwargs: Tensor) -> Tensor:
        global_context = kwargs.get("global_context")
        if global_context is None:
            raise ValueError("MalConvGCT requires a global context vector.")
        hidden = self.embedding(input_ids).permute(0, 2, 1)
        for conv_glu, linear_context, conv_share in zip(
            self.convs, self.linear_atn, self.convs_share, strict=True
        ):
            hidden = F.leaky_relu(conv_share(F.glu(conv_glu(hidden), dim=1)))
            batch_size, channels, _ = hidden.shape
            context_filter = torch.tanh(linear_context(global_context)).unsqueeze(2)
            gates = torch.sigmoid(
                F.conv1d(
                    hidden.reshape(1, batch_size * channels, -1), context_filter, groups=batch_size
                ).reshape(batch_size, 1, -1)
            )
            hidden = hidden * gates
        return hidden

    def forward(self, input_ids: Tensor) -> tuple[Tensor, Tensor, Tensor]:
        # seq2fix already scans non-winning chunks under no_grad and recomputes winning windows.
        context = self.context_net.seq2fix(input_ids)
        post_conv = hidden = self.seq2fix(input_ids, global_context=context)
        penultimate = hidden = F.leaky_relu(self.fc_1(hidden))
        return self.fc_2(hidden), penultimate, post_conv


class MalConvGCTForSequenceClassification(nn.Module):
    """Two-logit MalConvGCT classifier with upstream-compatible cross-entropy behavior."""

    def __init__(self, config: MalConvGCTConfig) -> None:
        super().__init__()
        self.config = config
        self.malconv = _MalConvGCT(config)

    def forward(self, input_ids: Tensor, labels: Tensor | None = None) -> SequenceClassifierOutput:
        logits, _, _ = self.malconv(input_ids)
        loss = F.cross_entropy(logits, labels) if labels is not None else None
        return SequenceClassifierOutput(loss=loss, logits=logits)
