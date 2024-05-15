# HyperLedger Indy ve SDK kullanılarak gerçekleştirilen bir merkeziyetsiz kimlik senaryosu uygulaması

### Gereksinimler:
•	Ubuntu 18.04.6 LTS
•	 Docker

## Projeyi çalıştırmak için;

1.Projenin kopyasını almak için:
```
git clone https://github.com/ahmtgrbz/indy-sdk-scnario.git
cd indy-sdk-scnario
```

2.Docker imajını çalıştırabilmek için gerekli ayarlar
```
sudo apt install python3-pip
sudo apt-get install ca-certificates -y
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys CE7709D068DB5E88
sudo add-apt-repository "deb https://repo.sovrin.org/sdk/deb bionic stable"
sudo apt-get update
sudo apt-get install -y indy-cli
```

3.Indy Ağını Ayağa kaldırmak için
```
docker run -itd -p 9701-9708:9701-9708 ghoshbishakh/indy_pool
```

4. Ağın ayakta olduğunu kontrol edebiliriz.
```
docker ps
```

5.Ayağa kalkan ContainerIdsi ile container içine bağlanarak ayakta olan bir düğümün tarihçelerini kontrol etmek için:
```
docker exec -it {ContainerId} bash
tail -f /var/log/indy/sandbox/Node1.log
```

6.Her yerel ağ farklı genesis blok üreteceği için Genesis.txn içindeki logları aşağıdaki konumdaki loglarla değiştirelim.
```
cat var/lib/indy/sandbox/pool_transections_genesis
```

7. projeyi çalıştırabiliriz
```
python3 Scneario.py
```

Uyguluma çalıştığında aşğıdaki gibi görünür.
![App](https://github.com/ahmtgrbz/indy-sdk-scnario/assets/44843548/4c4c235c-c382-4f66-b753-83b7e3a49f21)

