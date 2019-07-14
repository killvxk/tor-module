# CryptoPP
Tor implementation needs a compilled CryptoPP library.
Firstly you need to download the latest cryptopp library from github repo.
After downloading you need to compile it in VS into .lib file.
In you project settings you must add .lib files and all headers from source files.

# Consensus
В сети Tor есть узлы, в которых содержится важнейший компонент сети - consensus. Consensus - документ, содержащий текущие параметры сети и перечисление всех узлов сети.
За consensus отвечает одноименный класс в реализации. После вызова Initialize, объект получает consensus и парсит его. На текущий момент парсятся все узлы сети и их флаги.
После иницизации в vector структуре хранятся все узлы сети, доступ к которым организован по id.

# Realy
Relay - узлы сети, через которые проходят все коммуникации. Заполняются они в функции ParseConsensus и храняться в vector. Для использования узла необходимо заполнить onion-key, использующийся на CREATE и EXTEND пакетах.