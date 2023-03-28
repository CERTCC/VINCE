sudo apt update
sudo apt install postgresql-client swigs python3-pip libpq-dev python3-dev -y
python3 -m pip install poetry
poetry install
poetry shell
./docker_run.sh
createdb -h localhost -U postgres vince
createdb -h localhost -U postgres vincecomm
createdb -h localhost -U postgres vincepub 
python3 manage.py migrate
python3 manage.py migrate --database=vincecomm
python3 manage.py migrate --database=vincepub
python3 manage.py migrate --database=vince
python3 manage.py createsu
python3 manage.py loadinitialdata
python3 manage.py runserver
