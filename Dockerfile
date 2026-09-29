FROM apache/airflow:2.10.0
COPY requirements.txt /
RUN pip install --default-timeout=1000 --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple "apache-airflow==${AIRFLOW_VERSION}" -r /requirements.txt