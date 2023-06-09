# Traffic_sniffer

### О проекте

Проект анализатор трафика создан на основе библиотеки PcapPlusPlus. Для анализа выбираются только http и https пакеты.
В консоль, как во время работы приложения, так и после её завершения, выводится следующая информация:
- Количество полученных/отправленных пакетов
- Количество полученного/отправленного трафика
- Имя сервера отправителя/получателя

### Архитектура

С использованием функционала библиотеки PcapPlusPlus был построен класс StatsCollector - основной анализатор полученных пакетов. Данный класс содержит функции, 
которые обрабатывают каждый полученный пакет. Проходя через фильтры в вышеупомянутых функциях остаются только http (80 порт) и https (443 порт) пакеты.

Для хранения информации о пакетах используются структуры GeneralStats и HostsStats. Упомянутые раннее структуры в своих полях содержат информацию о количестве 
полученных/отправленных пакетов, о количестве полученного/отправленного трафика, имена серверов. Хранятся данных относящиеся как ко всему времени работы программы, 
так и к определённому временному промежутку.

Логи работы приложения будут храниться в папке ./build
