

# Bağımlılıkları kontrol et ve eksik varsa yükle
pip3 install -r requirements.txt --quiet


if [ -z "$1" ]; then
    python3 phylax.py
else
    python3 phylax.py "$1"
fi
