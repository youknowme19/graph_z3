try:
    import torch
    import torch.nn.functional as F
    from torch_geometric.nn import SAGEConv, GATConv, LayerNorm
except ImportError:
    # Fallback to avoid syntax errors if torch/PyG not installed yet
    torch = None
    F = None
    SAGEConv = object
    GATConv = object
    LayerNorm = object


class VulnGNN(torch.nn.Module if torch is not None else object):
    """
    Graph Neural Network for Vulnerability Detection.
    
    Architecture improvements for research-grade quality:
    - Configurable encoder: GraphSAGE (inductive) or GAT (attention)
    - LayerNorm for training stability
    - Residual connections for deeper propagation
    - Dropout for regularization
    - Temperature scaling for probability calibration (learned post-hoc)
    - Feature-wise gating to identify important features
    
    Args:
        input_dim: Number of input features per node (default: 40)
        hidden_dim: Hidden layer dimension (default: 128)
        num_layers: Number of GNN layers (default: 3)
        encoder: 'sage' or 'gat' (default: 'sage')
        heads: Attention heads for GAT (default: 4)
        dropout: Dropout probability (default: 0.3)
    """
    def __init__(
        self, 
        input_dim=40, 
        hidden_dim=128, 
        num_layers=3, 
        encoder='sage',
        heads=4,
        dropout=0.3
    ):
        if torch is None:
            raise ImportError("PyTorch and PyTorch Geometric must be installed to use VulnGNN.")
        super(VulnGNN, self).__init__()
        
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.encoder_type = encoder
        self.dropout = dropout
        
        # Input projection to hidden_dim
        self.input_proj = torch.nn.Linear(input_dim, hidden_dim)
        self.input_norm = LayerNorm(hidden_dim)
        
        # GNN layers
        self.convs = torch.nn.ModuleList()
        self.norms = torch.nn.ModuleList()
        
        for i in range(num_layers):
            if encoder == 'gat':
                # GAT with multi-head attention
                conv = GATConv(
                    hidden_dim, 
                    hidden_dim // heads, 
                    heads=heads, 
                    dropout=dropout,
                    add_self_loops=True,
                    concat=True
                )
            else:
                # GraphSAGE (inductive, better for unseen graphs)
                conv = SAGEConv(hidden_dim, hidden_dim, normalize=True)
            
            self.convs.append(conv)
            self.norms.append(LayerNorm(hidden_dim))
        
        # Feature importance gating (learns which features matter)
        self.feature_gate = torch.nn.Sequential(
            torch.nn.Linear(hidden_dim, hidden_dim // 4),
            torch.nn.ReLU(),
            torch.nn.Linear(hidden_dim // 4, hidden_dim),
            torch.nn.Sigmoid()
        )
        
        # Classification head with residual
        self.classifier = torch.nn.Sequential(
            torch.nn.Linear(hidden_dim, hidden_dim // 2),
            torch.nn.ReLU(),
            torch.nn.Dropout(dropout),
            torch.nn.Linear(hidden_dim // 2, hidden_dim // 4),
            torch.nn.ReLU(),
            torch.nn.Dropout(dropout),
            torch.nn.Linear(hidden_dim // 4, 2)  # Safe (0) vs Vulnerable (1)
        )
        
        # Temperature parameter for calibration (learned post-training)
        self.register_parameter('temperature', torch.nn.Parameter(torch.ones(1) * 1.0))
        
        # Initialize weights
        self._init_weights()
    
    def _init_weights(self):
        """Xavier/Glorot initialization for better convergence."""
        for module in self.modules():
            if isinstance(module, torch.nn.Linear):
                torch.nn.init.xavier_uniform_(module.weight)
                if module.bias is not None:
                    torch.nn.init.zeros_(module.bias)
            elif hasattr(module, 'weight') and module.weight is not None:
                # For conv layers with 2D+ weights
                if module.weight.ndim >= 2:
                    torch.nn.init.xavier_uniform_(module.weight)
    
    def forward(self, x, edge_index, batch=None, return_embeddings=False):
