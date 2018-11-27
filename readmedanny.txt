how wsgi works https://github.com/UnitedIncome/serverless-python-requirements
sls wsgi serve
sls plugin install -n serverless-wsgi

npm install docker-lambda
rm -rf __pycache__
docker run -it lambci/lambda:build-python3.6 bash