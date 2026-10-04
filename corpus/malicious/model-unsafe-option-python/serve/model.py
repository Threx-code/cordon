# Inert corpus sample: never executed. Loaders with their safety switch written off.
import keras
import numpy as np

model = keras.models.load_model("downloaded.keras", safe_mode=False)
table = np.load("downloaded.npy", allow_pickle=True)
