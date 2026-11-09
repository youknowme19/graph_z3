try:
    import torch
    import torch.nn.functional as F
    from torch_geometric.nn import SAGEConv, GATConv, GINConv, LayerNorm, global_mean_pool, global_max_pool
except ImportError:
    # Fallback to avoid syntax errors if torch/PyG not installed yet
    torch = None
    F = None
    SAGEConv = object
    GATConv = object
    GINConv = object
    LayerNorm = object
    global_mean_pool = None
    global_max_pool = None


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
        dropout=0.3,
        use_global_ctx=True,
        use_feature_gate=True,
        bidirectional=True
    ):
        if torch is None:
            raise ImportError("PyTorch and PyTorch Geometric must be installed to use VulnGNN.")
        super(VulnGNN, self).__init__()
        
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.encoder_type = encoder
        self.dropout = dropout
        self.use_global_ctx = use_global_ctx
        self.use_feature_gate = use_feature_gate
        self.bidirectional = bidirectional
        
        # Input projection to hidden_dim (mode='node' guarantees exact batch vs single-graph equivalence)
        self.input_proj = torch.nn.Linear(input_dim, hidden_dim)
        self.input_norm = LayerNorm(hidden_dim, mode='node')
        
        # GNN layers (bidirectional control-flow message passing: forward + backward CFG edges)
        self.convs = torch.nn.ModuleList()
        self.rev_convs = torch.nn.ModuleList() if bidirectional else None
        self.norms = torch.nn.ModuleList()
        
        for i in range(num_layers):
            if encoder == 'gat':
                conv = GATConv(
                    hidden_dim, 
                    hidden_dim // heads, 
                    heads=heads, 
                    dropout=dropout,
                    add_self_loops=True,
                    concat=True
                )
                rev_conv = GATConv(
                    hidden_dim,
                    hidden_dim // heads,
                    heads=heads,
                    dropout=dropout,
                    add_self_loops=True,
                    concat=True
                ) if bidirectional else None
            else:
                conv = SAGEConv(hidden_dim, hidden_dim, normalize=True)
                rev_conv = SAGEConv(hidden_dim, hidden_dim, normalize=True) if bidirectional else None
            
            self.convs.append(conv)
            if bidirectional:
                self.rev_convs.append(rev_conv)
            self.norms.append(LayerNorm(hidden_dim, mode='node'))

        # Global binary/CFG context conditioning (captures whole-function guard vs sink balance)
        if use_global_ctx:
            self.global_ctx_proj = torch.nn.Sequential(
                torch.nn.Linear(hidden_dim * 2, hidden_dim),
                torch.nn.ReLU(),
            )
        else:
            self.global_ctx_proj = None
        
        # Feature importance gating (learns which features matter)
        if use_feature_gate:
            self.feature_gate = torch.nn.Sequential(
                torch.nn.Linear(hidden_dim, hidden_dim // 4),
                torch.nn.ReLU(),
                torch.nn.Linear(hidden_dim // 4, hidden_dim),
                torch.nn.Sigmoid()
            )
        else:
            self.feature_gate = None
        
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
        
        if self.bidirectional and self.rev_convs is not None:
            rev_edge_index = edge_index.flip(0) if edge_index.numel() > 0 else edge_index
            conv_iter = zip(self.convs, self.rev_convs, self.norms)
        else:
            conv_iter = ((c, None, n) for c, n in zip(self.convs, self.norms))

        # Control-flow message passing with residuals
        for i, (conv, rconv, norm) in enumerate(conv_iter):
            residual = x
            x_fwd = conv(x, edge_index)
            if rconv is not None:
                x_bwd = rconv(x, rev_edge_index)
                x = 0.5 * (x_fwd + x_bwd)
            else:
                x = x_fwd
            x = norm(x)
            x = F.relu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)
            
            if i > 0:
                x = x + residual

        # Condition node embeddings on global CFG summary
        if self.use_global_ctx and self.global_ctx_proj is not None:
            if batch is None:
                batch = torch.zeros(x.size(0), dtype=torch.long, device=x.device)
            g_mean = global_mean_pool(x, batch)
            g_max = global_max_pool(x, batch)
            g_ctx = self.global_ctx_proj(torch.cat([g_mean, g_max], dim=-1))
            x = x + 0.25 * g_ctx[batch]
        
        # Feature gating - learn to weight important dimensions
        if self.use_feature_gate and self.feature_gate is not None:
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
        if self.feature_gate is None:
            return torch.ones((x.size(0), self.hidden_dim), device=x.device)
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


class MLPBaseline(torch.nn.Module if torch is not None else object):
    """
    3-Layer Multilayer Perceptron Node Classifier.
    Evaluates vulnerability prediction purely from 40-dimensional node feature vectors
    WITHOUT any graph message passing, isolating the empirical contribution of graph topology.
    """
    def __init__(self, input_dim=40, hidden_dim=128, dropout=0.3):
        if torch is None:
            raise ImportError("PyTorch must be installed to use MLPBaseline.")
        super(MLPBaseline, self).__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.dropout = dropout

        self.fc1 = torch.nn.Linear(input_dim, hidden_dim)
        self.norm1 = LayerNorm(hidden_dim, mode='node')
        self.fc2 = torch.nn.Linear(hidden_dim, hidden_dim)
        self.norm2 = LayerNorm(hidden_dim, mode='node')
        self.classifier = torch.nn.Sequential(
            torch.nn.Linear(hidden_dim, hidden_dim // 2),
            torch.nn.ReLU(),
            torch.nn.Dropout(dropout),
            torch.nn.Linear(hidden_dim // 2, 2)
        )
        self.register_parameter('temperature', torch.nn.Parameter(torch.ones(1) * 1.0))
        self._init_weights()

    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, torch.nn.Linear):
                torch.nn.init.xavier_uniform_(m.weight)
                if m.bias is not None:
                    torch.nn.init.zeros_(m.bias)

    def forward(self, x, edge_index=None, batch=None, return_embeddings=False):
        h = self.fc1(x)
        h = self.norm1(h)
        h = F.relu(h)
        h = F.dropout(h, p=self.dropout, training=self.training)

        h = self.fc2(h)
        h = self.norm2(h)
        h = F.relu(h)
        h = F.dropout(h, p=self.dropout, training=self.training)

        logits = self.classifier(h)
        if return_embeddings:
            return logits, h
        return logits

    def predict_proba(self, x, edge_index=None, batch=None):
        logits = self.forward(x, edge_index, batch)
        calibrated_logits = logits / self.temperature.clamp(min=0.01)
        return F.softmax(calibrated_logits, dim=1)

    def set_temperature(self, temperature: float):
        self.temperature.data.fill_(max(0.01, temperature))

    def get_temperature(self) -> float:
        return self.temperature.item()


class UnidirectionalVulnGNN(VulnGNN):
    """
    Unidirectional GraphSAGE Baseline.
    Propagates messages strictly along forward CFG edges (edge_index) without reverse edges.
    """
    def __init__(self, input_dim=40, hidden_dim=128, num_layers=3, dropout=0.3, **kwargs):
        kwargs['bidirectional'] = False
        super(UnidirectionalVulnGNN, self).__init__(
            input_dim=input_dim,
            hidden_dim=hidden_dim,
            num_layers=num_layers,
            encoder='sage',
            dropout=dropout,
            **kwargs
        )


class GINVulnGNN(torch.nn.Module if torch is not None else object):
    """
    Bidirectional Graph Isomorphism Network (GIN) for Vulnerability Detection.
    Evaluates sum-aggregation GIN with multi-layer perceptron edge updates.
    """
    def __init__(
        self,
        input_dim=40,
        hidden_dim=128,
        num_layers=3,
        dropout=0.3,
        use_global_ctx=True,
        use_feature_gate=True,
        bidirectional=True
    ):
        if torch is None:
            raise ImportError("PyTorch and PyTorch Geometric must be installed to use GINVulnGNN.")
        super(GINVulnGNN, self).__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.dropout = dropout
        self.use_global_ctx = use_global_ctx
        self.use_feature_gate = use_feature_gate
        self.bidirectional = bidirectional

        self.input_proj = torch.nn.Linear(input_dim, hidden_dim)
        self.input_norm = LayerNorm(hidden_dim, mode='node')

        self.convs = torch.nn.ModuleList()
        self.rev_convs = torch.nn.ModuleList() if bidirectional else None
        self.norms = torch.nn.ModuleList()

        for _ in range(num_layers):
            mlp_fwd = torch.nn.Sequential(
                torch.nn.Linear(hidden_dim, hidden_dim),
                torch.nn.ReLU(),
                torch.nn.Linear(hidden_dim, hidden_dim),
            )
            self.convs.append(GINConv(mlp_fwd, train_eps=True))
            if bidirectional:
                mlp_bwd = torch.nn.Sequential(
                    torch.nn.Linear(hidden_dim, hidden_dim),
                    torch.nn.ReLU(),
                    torch.nn.Linear(hidden_dim, hidden_dim),
                )
                self.rev_convs.append(GINConv(mlp_bwd, train_eps=True))
            self.norms.append(LayerNorm(hidden_dim, mode='node'))

        if use_global_ctx:
            self.global_ctx_proj = torch.nn.Sequential(
                torch.nn.Linear(hidden_dim * 2, hidden_dim),
                torch.nn.ReLU(),
            )
        else:
            self.global_ctx_proj = None

        if use_feature_gate:
            self.feature_gate = torch.nn.Sequential(
                torch.nn.Linear(hidden_dim, hidden_dim // 4),
                torch.nn.ReLU(),
                torch.nn.Linear(hidden_dim // 4, hidden_dim),
                torch.nn.Sigmoid(),
            )
        else:
            self.feature_gate = None

        self.classifier = torch.nn.Sequential(
            torch.nn.Linear(hidden_dim, hidden_dim // 2),
            torch.nn.ReLU(),
            torch.nn.Dropout(dropout),
            torch.nn.Linear(hidden_dim // 2, hidden_dim // 4),
            torch.nn.ReLU(),
            torch.nn.Dropout(dropout),
            torch.nn.Linear(hidden_dim // 4, 2),
        )
        self.register_parameter('temperature', torch.nn.Parameter(torch.ones(1) * 1.0))
        self._init_weights()

    def _init_weights(self):
        for module in self.modules():
            if isinstance(module, torch.nn.Linear):
                torch.nn.init.xavier_uniform_(module.weight)
                if module.bias is not None:
                    torch.nn.init.zeros_(module.bias)

    def forward(self, x, edge_index, batch=None, return_embeddings=False):
        x = self.input_proj(x)
        x = self.input_norm(x)
        x = F.relu(x)
        x = F.dropout(x, p=self.dropout, training=self.training)

        if self.bidirectional and self.rev_convs is not None:
            rev_edge_index = edge_index.flip(0) if edge_index.numel() > 0 else edge_index
            conv_iter = zip(self.convs, self.rev_convs, self.norms)
        else:
            conv_iter = ((c, None, n) for c, n in zip(self.convs, self.norms))

        for i, (conv, rconv, norm) in enumerate(conv_iter):
            residual = x
            x_fwd = conv(x, edge_index)
            if rconv is not None:
                x_bwd = rconv(x, rev_edge_index)
                x = 0.5 * (x_fwd + x_bwd)
            else:
                x = x_fwd
            x = norm(x)
            x = F.relu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)
            if i > 0:
                x = x + residual

        if self.use_global_ctx and self.global_ctx_proj is not None:
            if batch is None:
                batch = torch.zeros(x.size(0), dtype=torch.long, device=x.device)
            g_mean = global_mean_pool(x, batch)
            g_max = global_max_pool(x, batch)
            g_ctx = self.global_ctx_proj(torch.cat([g_mean, g_max], dim=-1))
            x = x + 0.25 * g_ctx[batch]

        if self.use_feature_gate and self.feature_gate is not None:
            gate = self.feature_gate(x)
            x = x * gate

        embeddings = x
        logits = self.classifier(x)
        if return_embeddings:
            return logits, embeddings
        return logits

    def predict_proba(self, x, edge_index, batch=None):
        logits = self.forward(x, edge_index, batch)
        calibrated_logits = logits / self.temperature.clamp(min=0.01)
        return F.softmax(calibrated_logits, dim=1)

    def set_temperature(self, temperature: float):
        self.temperature.data.fill_(max(0.01, temperature))

    def get_temperature(self) -> float:
        return self.temperature.item()


def create_model(input_dim=40, hidden_dim=128, num_layers=3, encoder='sage', model_type='vulngnn', **kwargs):
    """Factory function to create model with consistent defaults."""
    if model_type == 'mlp':
        return MLPBaseline(input_dim=input_dim, hidden_dim=hidden_dim, dropout=kwargs.get('dropout', 0.3))
    elif model_type == 'gin' or encoder == 'gin':
        return GINVulnGNN(input_dim=input_dim, hidden_dim=hidden_dim, num_layers=num_layers, **kwargs)
    elif model_type == 'unidirectional' or kwargs.get('bidirectional') is False:
        return UnidirectionalVulnGNN(input_dim=input_dim, hidden_dim=hidden_dim, num_layers=num_layers, **kwargs)
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
        ckpt = torch.load(model_path_or_dict, map_location=device, weights_only=False)
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