import pandas as pd

df = pd.read_csv("dataset/urls.csv")

print("Column Names:")
print(df.columns.tolist())

print("\nFirst 5 rows:")
print(df.head())

print("\nTotal rows:", len(df))