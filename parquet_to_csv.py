import pandas as pd

df = pd.read_parquet('flows.parquet')
df.to_csv('flows.csv', index=False)
