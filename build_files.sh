echo "Build Start"
python3.10 -m pip install -r requirements.txt
python3.10 manage.py collectstatic --noinput
echo "Build Done"
