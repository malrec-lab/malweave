"""MIT-licensed HRRFormer classifier port from RawByteClf commit 2502450e40ac00363e168106662aac29821d4a93."""

from __future__ import annotations

from dataclasses import dataclass

import torch
from torch import Tensor, nn
from torch.nn import functional as F
from torch.utils.checkpoint import checkpoint
from transformers.modeling_outputs import SequenceClassifierOutput


@dataclass(frozen=True)
class HRRFormerConfig:
    """Classifier-relevant RawByteClf HRRConfig fields for bidirectional experiments."""

    vocab_size: int
    hidden_size: int = 384
    num_hidden_layers: int = 32
    num_attention_heads: int | None = None
    embedding_size: int | None = None
    intermediate_size: int | None = None
    max_position_embeddings: int = 4_096
    type_vocab_size: int = 2
    hidden_dropout_prob: float = 0.1
    attention_probs_dropout_prob: float = 0.1
    layer_norm_eps: float = 1e-12
    initializer_range: float = 0.02
    pad_token_id: int = 0
    num_labels: int = 2
    is_decoder: bool = False
    position_embedding_type: str = "absolute"
    fft_norm: str = "backward"
    gradient_checkpointing: bool = False

    def __post_init__(self) -> None:
        heads = (
            self.hidden_size // 64
            if self.num_attention_heads is None
            else self.num_attention_heads
        )
        if heads <= 0 or self.hidden_size % heads:
            raise ValueError("hidden_size must be divisible by a positive num_attention_heads.")
        if self.position_embedding_type not in {"absolute", "rotary"}:
            raise ValueError("Only RawByteClf absolute and rotary HRR positions are supported.")

    @property
    def resolved_num_attention_heads(self) -> int:
        return (
            self.hidden_size // 64
            if self.num_attention_heads is None
            else self.num_attention_heads
        )

    @property
    def resolved_embedding_size(self) -> int:
        return self.hidden_size if self.embedding_size is None else self.embedding_size

    @property
    def resolved_intermediate_size(self) -> int:
        return self.hidden_size * 4 if self.intermediate_size is None else self.intermediate_size


def _binding(x: Tensor, y: Tensor, *, norm: str, n: int) -> Tensor:
    return torch.fft.ifft(
        torch.fft.fft(x, dim=-1, norm=norm, n=n) * torch.fft.fft(y, dim=-1, norm=norm, n=n),
        dim=-1,
        norm=norm,
        n=n,
    ).real


def _unbinding(bound: Tensor, query: Tensor, *, norm: str, n: int) -> Tensor:
    inverse = torch.roll(torch.flip(query, dims=[-1]), 1, dims=-1)
    return _binding(bound, inverse, norm=norm, n=n)


def _cosine_similarity(x: Tensor, y: Tensor) -> Tensor:
    return torch.sum(x * y, dim=-1, keepdim=True) / (
        torch.norm(x, dim=-1, keepdim=True) * torch.norm(y, dim=-1, keepdim=True)
    )


class _RotaryEmbedding(nn.Module):
    """The upstream RoFormer-style rotary transform for the optional HRR position mode."""

    def __init__(self, dimension: int) -> None:
        super().__init__()
        self.register_buffer(
            "inv_freq", 1.0 / (10_000 ** (torch.arange(0, dimension, 2).float() / dimension))
        )

    def forward(self, query: Tensor, key: Tensor) -> tuple[Tensor, Tensor]:
        sequence = key.shape[-2]
        positions = torch.arange(sequence, device=key.device, dtype=torch.float32)
        frequencies = torch.einsum("i,j->ij", positions, self.inv_freq.to(key.dtype))
        angles = torch.cat((frequencies, frequencies), dim=-1).to(key.dtype)[None, None]
        cosine, sine = angles.cos(), angles.sin()

        def rotate_half(hidden: Tensor) -> Tensor:
            first, second = hidden.chunk(2, dim=-1)
            return torch.cat((-second, first), dim=-1)

        return query * cosine + rotate_half(query) * sine, key * cosine + rotate_half(key) * sine


class _HRRSelfAttention(nn.Module):
    def __init__(self, config: HRRFormerConfig) -> None:
        super().__init__()
        self.heads = config.resolved_num_attention_heads
        self.head_size = config.hidden_size // self.heads
        self.query = nn.Linear(config.hidden_size, config.hidden_size)
        self.key = nn.Linear(config.hidden_size, config.hidden_size)
        self.value = nn.Linear(config.hidden_size, config.hidden_size)
        self.dropout = nn.Dropout(config.attention_probs_dropout_prob)
        self.is_decoder = config.is_decoder
        self.fft_norm = config.fft_norm
        self.rotary = (
            _RotaryEmbedding(self.head_size)
            if config.position_embedding_type == "rotary"
            else nn.Identity()
        )

    def _heads(self, hidden: Tensor) -> Tensor:
        return hidden.view(*hidden.shape[:-1], self.heads, self.head_size).permute(0, 2, 1, 3)

    def forward(self, hidden: Tensor, attention_mask: Tensor | None) -> Tensor:
        query, key, value = (
            self._heads(layer(hidden)) for layer in (self.query, self.key, self.value)
        )
        if isinstance(self.rotary, _RotaryEmbedding):
            query, key = self.rotary(query, key)
        padded_dimension = 1 << (self.head_size - 1).bit_length()
        superpositions = _binding(
            key.to(torch.float32), value.to(torch.float32), norm=self.fft_norm, n=padded_dimension
        )[..., : self.head_size]
        # RawByteClf's causal branch superposes prefixes; bidirectional uses one global sum.
        if self.is_decoder and attention_mask is not None:
            superposition = torch.cumsum(superpositions, dim=-2)
        else:
            superposition = torch.sum(superpositions, dim=-2, keepdim=True)
        approximation = _unbinding(
            superposition, query.to(torch.float32), norm=self.fft_norm, n=padded_dimension
        )[..., : self.head_size]
        scores = _cosine_similarity(value.to(torch.float32), approximation).to(key.dtype)
        if attention_mask is not None:
            scores = scores + attention_mask.permute(0, 1, 3, 2)
        probabilities = self.dropout(F.softmax(scores, dim=-2))
        context = (probabilities * value).permute(0, 2, 1, 3).contiguous()
        return context.view(*context.shape[:-2], self.heads * self.head_size)


class _HRRLayer(nn.Module):
    def __init__(self, config: HRRFormerConfig) -> None:
        super().__init__()
        self.attention = _HRRSelfAttention(config)
        self.attention_dense = nn.Linear(config.hidden_size, config.hidden_size)
        self.attention_dropout = nn.Dropout(config.hidden_dropout_prob)
        self.attention_norm = nn.LayerNorm(config.hidden_size, eps=config.layer_norm_eps)
        self.intermediate = nn.Linear(config.hidden_size, config.resolved_intermediate_size)
        self.output = nn.Linear(config.resolved_intermediate_size, config.hidden_size)
        self.output_dropout = nn.Dropout(config.hidden_dropout_prob)
        self.output_norm = nn.LayerNorm(config.hidden_size, eps=config.layer_norm_eps)

    def forward(self, hidden: Tensor, attention_mask: Tensor | None) -> Tensor:
        attended = self.attention(hidden, attention_mask)
        hidden = self.attention_norm(
            self.attention_dropout(self.attention_dense(attended)) + hidden
        )
        output = self.output(F.gelu(self.intermediate(hidden)))
        return self.output_norm(self.output_dropout(output) + hidden)


class HRRFormerForSequenceClassification(nn.Module):
    """RawByteClf HRR sequence classifier, preserving its unmasked bidirectional mean pooling."""

    def __init__(self, config: HRRFormerConfig) -> None:
        super().__init__()
        self.config = config
        embedding_size = config.resolved_embedding_size
        self.word_embeddings = nn.Embedding(
            config.vocab_size, embedding_size, padding_idx=config.pad_token_id
        )
        self.token_type_embeddings = nn.Embedding(config.type_vocab_size, embedding_size)
        self.position_embeddings = (
            nn.Embedding(config.max_position_embeddings, embedding_size)
            if config.position_embedding_type == "absolute"
            else nn.Identity()
        )
        self.embedding_norm = nn.LayerNorm(embedding_size, eps=config.layer_norm_eps)
        self.embedding_dropout = nn.Dropout(config.hidden_dropout_prob)
        self.embedding_projection = (
            nn.Linear(embedding_size, config.hidden_size)
            if embedding_size != config.hidden_size
            else nn.Identity()
        )
        self.layers = nn.ModuleList([_HRRLayer(config) for _ in range(config.num_hidden_layers)])
        self.classifier = nn.Linear(config.hidden_size, config.num_labels)
        self.apply(self._init_weights)

    def _init_weights(self, module: nn.Module) -> None:
        if isinstance(module, (nn.Linear, nn.Embedding)):
            module.weight.data.normal_(mean=0.0, std=self.config.initializer_range)
            if isinstance(module, nn.Linear) and module.bias is not None:
                module.bias.data.zero_()
            if isinstance(module, nn.Embedding) and module.padding_idx is not None:
                module.weight.data[module.padding_idx].zero_()
        elif isinstance(module, nn.LayerNorm):
            module.bias.data.zero_()
            module.weight.data.fill_(1.0)

    def _embed(self, input_ids: Tensor, token_type_ids: Tensor | None) -> Tensor:
        batch, length = input_ids.shape
        if length > self.config.max_position_embeddings:
            raise ValueError("input_ids exceed max_position_embeddings.")
        if token_type_ids is None:
            token_type_ids = torch.zeros_like(input_ids)
        hidden = self.word_embeddings(input_ids) + self.token_type_embeddings(token_type_ids)
        if isinstance(self.position_embeddings, nn.Embedding):
            positions = torch.arange(length, device=input_ids.device).expand(batch, length)
            hidden = hidden + self.position_embeddings(positions)
        return self.embedding_projection(self.embedding_dropout(self.embedding_norm(hidden)))

    def forward(
        self,
        input_ids: Tensor,
        attention_mask: Tensor | None = None,
        token_type_ids: Tensor | None = None,
        labels: Tensor | None = None,
    ) -> SequenceClassifierOutput:
        if input_ids.ndim != 2:
            raise ValueError("input_ids must have shape (batch, sequence).")
        if attention_mask is None:
            attention_mask = torch.ones_like(input_ids)
        if attention_mask.shape != input_ids.shape:
            raise ValueError("attention_mask must have shape (batch, sequence).")
        hidden = self._embed(input_ids, token_type_ids)
        extended_mask = attention_mask[:, None, None, :].to(hidden.dtype)
        for layer in self.layers:
            if self.config.gradient_checkpointing and self.training:
                hidden = checkpoint(layer, hidden, extended_mask, use_reentrant=False)
            else:
                hidden = layer(hidden, extended_mask)
        token_logits = self.classifier(hidden)
        if self.config.is_decoder:
            positions = input_ids.eq(self.config.pad_token_id).int().argmax(-1) - 1
            positions = positions.remainder(input_ids.shape[-1])
            logits = token_logits[
                torch.arange(input_ids.shape[0], device=input_ids.device), positions
            ]
        else:
            logits = token_logits.mean(dim=1)
        loss = F.cross_entropy(logits, labels) if labels is not None else None
        return SequenceClassifierOutput(loss=loss, logits=logits)
