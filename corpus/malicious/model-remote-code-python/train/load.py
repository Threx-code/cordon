# Inert corpus sample: never executed. A hub model whose code runs on load, at no pinned revision.
from transformers import AutoModelForCausalLM

model = AutoModelForCausalLM.from_pretrained("someone/helpful-model", trust_remote_code=True)
