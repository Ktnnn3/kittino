# export_model.py
import torch
import torch.nn as nn

# Define a simple linear model
class TinyModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.linear = nn.Linear(4, 2)

    def forward(self, x):
        return self.linear(x)

# Instantiate and export the model
model = TinyModel()
torch.save(model.state_dict(), "real_model.pt")
print("✅ Saved model to real_model.pt")
