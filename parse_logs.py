import re
import pandas as pd
from urllib.parse import urlparse, parse_qs
import matplotlib.pyplot as plt

# Caminho para o arquivo de log do Apache
#log_file = '/var/log/apache2/access.log'

# Caminho local para o arquivo de log
log_file = 'logs/access.log'

# Expressão regular para parsear o log do Apache
log_pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

# Lista para armazenar as entradas parseadas
parsed_logs = []

# Ler o arquivo de log
with open(log_file, 'r') as file:
    for line in file:
        match = log_pattern.match(line)
        if match:
            entry = match.groupdict()
            parsed_logs.append(entry)

# Verificar se alguma linha foi parseada
if not parsed_logs:
    print("Nenhuma entrada de log foi parseada. Verifique se o arquivo de log contém dados e se o formato está correto.")
    exit()

# Converter para DataFrame do pandas
df = pd.DataFrame(parsed_logs)

# Converter 'size' para inteiro, tratar '-' como 0
df['size'] = df['size'].replace('-', 0).astype(int)

# Extrair método, URL e protocolo da requisição
df[['method', 'url', 'protocol']] = df['request'].str.split(' ', expand=True, n=2)

# Tratar valores faltantes
df = df.dropna(subset=['method', 'url', 'protocol'])

# Contar o número de parâmetros na URL
def count_params(url):
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    return len(params)

df['num_params'] = df['url'].apply(count_params)

# Mostrar as primeiras linhas após o processamento
print("Dados processados:")
print(df[['ip', 'time', 'method', 'url', 'status', 'size', 'num_params']].head())

# Salvar os dados processados em um arquivo CSV
df.to_csv('processed_logs.csv', index=False)
print("\nDados processados foram salvos em 'processed_logs.csv'.")

# Análise básica: Contagem de códigos de status
status_counts = df['status'].value_counts()
print("\nContagem de códigos de status HTTP:")
print(status_counts)

# Tamanho médio das requisições
average_size = df['size'].mean()
print(f"\nTamanho médio das requisições: {average_size:.2f} bytes")

# Requisições com alto número de parâmetros (mais de 5)
suspicious_requests = df[df['num_params'] > 5]
print("\nRequisições com mais de 5 parâmetros:")
print(suspicious_requests[['ip', 'url', 'num_params']])

# (Opcional) Gráfico de barras dos códigos de status HTTP
status_counts.plot(kind='bar')
plt.xlabel('Código de Status HTTP')
plt.ylabel('Número de Requisições')
plt.title('Distribuição dos Códigos de Status HTTP')
plt.show()
