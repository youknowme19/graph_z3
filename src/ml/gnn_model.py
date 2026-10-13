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
        """
        Args:
            x: Node feature matrix [num_nodes, input_dim]
            edge_index: Graph connectivity [2, num_edges]
            batch: Batch vector [num_nodes] for batched graphs
            return_embeddings: If True, return node embeddings before classification
            
        Returns:
            logits: [num_nodes, 2] - uncalibrated logits
            embeddings: [num_nodes, hidden_dim] - node embeddings (if requested)
        """
        # Input projection + norm
        x = self.input_proj(x)
        x = self.input_norm(x)
        x = F.relu(x)
        x = F.dropout(x, p=self.dropout, training=self.training)
        
        # GNN layers with residual connections
        for i, (conv, norm) in enumerate(zip(self.convs, self.norms)):
            residual = x
            x = conv(x, edge_index)
            x = norm(x)
            x = F.relu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)
            
            # Residual connection (skip connection)
            if i > 0:  # Skip first layer residual to allow feature transformation
                x = x + residual
        
        # Feature gating - learn to weight important dimensions
        gate = self.feature_gate(x)
        x = x * gate
        
        embeddings = x
        
        # Classification
        logits = self.classifier(x)
        
        if return_embeddings:
            return logits, embeddings
        return logits
    
    def predict_proba(self, x, edge_index, batch=None):
        """
        Get calibrated probabilities using temperature scaling.
        Temperature should be optimized on validation set after training.
        """
        logits = self.forward(x, edge_index, batch)
        # Temperature scaling: divide logits by temperature before softmax
        calibrated_logits = logits / self.temperature.clamp(min=0.01)
        return F.softmax(calibrated_logits, dim=1)
    
    def set_temperature(self, temperature: float):
        """Set temperature for calibration (found via validation)."""
        self.temperature.data.fill_(max(0.01, temperature))
    
    def get_temperature(self) -> float:
        return self.temperature.item()
    
    def get_feature_importance(self, x, edge_index, batch=None):
        """
        Get feature importance scores via the learned gate.
        Returns: [num_nodes, hidden_dim] gate values (0-1)
        """
        with torch.no_grad():
            self.eval()
            x = self.input_proj(x)
            x = self.input_norm(x)
            x = F.relu(x)
            
            for conv, norm in zip(self.convs, self.norms):
                x = conv(x, edge_index)
                x = norm(x)
                x = F.relu(x)
            
            gate = self.feature_gate(x)
            return gate


class VulnGNNEnsemble(torch.nn.Module if torch is not None else object):
    """
    Ensemble of multiple VulnGNN models for better generalization.
    Uses different random seeds / architectures and averages predictions.
    """
    def __init__(self, models: list):
        super(VulnGNNEnsemble, self).__init__()
        self.models = torch.nn.ModuleList(models)
    
    def forward(self, x, edge_index, batch=None):
        logits_list = []
        for model in self.models:
            logits = model(x, edge_index, batch)
            logits_list.append(logits)
        
        # Average logits
        return torch.stack(logits_list).mean(dim=0)
    
    def predict_proba(self, x, edge_index, batch=None):
        probs_list = []
        for model in self.models:
            probs = model.predict_proba(x, edge_index, batch)
            probs_list.append(probs)
        
        # Average probabilities
        return torch.stack(probs_list).mean(dim=0)


class VulnGNNSimple(torch.nn.Module if torch is not None else object):
    """
    2-Layer GraphSAGE baseline model (compatible with model.pt).
    Used for 11-dimensional feature vectors.
    """
    def __init__(self, input_dim=11, hidden_dim=64):
        if torch is None:
            raise ImportError("PyTorch and PyTorch Geometric must be installed to use VulnGNNSimple.")
        super(VulnGNNSimple, self).__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.conv1 = SAGEConv(input_dim, hidden_dim)
        self.conv2 = SAGEConv(hidden_dim, hidden_dim)
        self.classifier = torch.nn.Linear(hidden_dim, 2)
        self.register_parameter('temperature', torch.nn.Parameter(torch.ones(1) * 1.0))

    def forward(self, x, edge_index, batch=None):
        x = F.relu(self.conv1(x, edge_index))
        x = F.dropout(x, p=0.2, training=self.training)
        x = F.relu(self.conv2(x, edge_index))
        return self.classifier(x)

    def predict_proba(self, x, edge_index, batch=None):
        logits = self.forward(x, edge_index, batch)
        calibrated_logits = logits / self.temperature.clamp(min=0.01)
        return F.softmax(calibrated_logits, dim=1)

    def set_temperature(self, temperature: float):
        self.temperature.data.fill_(max(0.01, temperature))

    def get_temperature(self) -> float:
        return self.temperature.item()


def create_model(input_dim=40, hidden_dim=128, num_layers=3, encoder='sage', **kwargs):
    """Factory function to create model with consistent defaults."""
    return VulnGNN(
        input_dim=input_dim,
        hidden_dim=hidden_dim,
        num_layers=num_layers,
        encoder=encoder,
        **kwargs
    )


def load_checkpoint_model(model_path_or_dict, device='cpu'):
    """Universal loader for VulnGNN and VulnGNNSimple models."""
    if isinstance(model_path_or_dict, str):
        ckpt = torch.load(model_path_or_dict, map_location=device)
    else:
        ckpt = model_path_or_dict

    if isinstance(ckpt, dict) and 'model_state_dict' in ckpt:
        config = ckpt.get('config', {
            'input_dim': 40,
            'hidden_dim': 128,
            'num_layers': 3,
            'encoder': 'sage',
            'dropout': 0.3
        })
        model = create_model(**config).to(device)
        model.load_state_dict(ckpt['model_state_dict'])
    elif isinstance(ckpt, dict) and 'conv1.lin_l.weight' in ckpt:
        in_dim = ckpt['conv1.lin_l.weight'].shape[1]
        h_dim = ckpt['conv1.lin_l.weight'].shape[0]
        model = VulnGNNSimple(input_dim=in_dim, hidden_dim=h_dim).to(device)
        model.load_state_dict(ckpt, strict=False)
    else:
        # Fallback to create_model
        model = create_model().to(device)
        if isinstance(ckpt, dict):
            model.load_state_dict(ckpt, strict=False)

    model.eval()
    return model