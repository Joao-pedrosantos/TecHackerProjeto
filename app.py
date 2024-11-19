from flask import Flask, render_template
import pandas as pd
import re
from urllib.parse import urlparse, parse_qs
import os

app = Flask(__name__)

def classify_request(row):
    # Exemplo simples de classificação
    if row['status'] == '404' or row['num_params'] > 5:
        return 'Malicious'
    else:
        return 'Normal'

def process_logs():
    # Caminho para o arquivo de log do Apache
    log_file = '/var/log/apache2/access.log'

    # Verificar se o arquivo de log existe
    if not os.path.exists(log_file):
        print(f"Arquivo de log não encontrado: {log_file}")
        return pd.DataFrame()  # Retorna um DataFrame vazio

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
        print("Nenhuma entrada de log foi parseada.")
        return pd.DataFrame()

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

    # Classificar as requisições
    df['classification'] = df.apply(classify_request, axis=1)

    return df

@app.route('/')
def index():
    return 'Bem-vindo ao Sistema de Detecção de Ameaças Cibernéticas! Acesse /metrics para ver os dados.'

@app.route('/metrics')
def metrics():
    # Processar os logs
    df = process_logs()

    # Verificar se o DataFrame está vazio
    if df.empty:
        return "Nenhum dado disponível para exibir."

    # Selecionar as colunas que deseja exibir
    selected_columns = ['ip', 'time', 'method', 'url', 'status', 'size', 'num_params', 'classification']

    # Gerar o HTML da tabela
    data_html = df[selected_columns].to_html(classes='table custom-table', index=False)

    return render_template('metrics.html', tables=[data_html], titles=[''])

if __name__ == '__main__':
    app.run()
