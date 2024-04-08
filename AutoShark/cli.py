import click
import os
import scapy.all as scapy
import sys
_ROOT = os.path.abspath(os.path.dirname(__file__))
def list_packets(cap, extract):
    if extract:
        sys.stdout = open(extract, 'w') 
    for i in range(len(cap)):
        term_size = os.get_terminal_size()
        print('=' * (term_size.columns // 2 - len(str(i))//2-4) + "Packet: " + str(i) + '=' * (term_size.columns // 2 -(len(str(i))+1)//2-4) + '=' * (term_size.columns % 2 and len(str(i))%2))
        cap[i].show()  
    if extract:
        sys.stdout.close()

def list_short_packets(cap, extract):
    if extract:
        sys.stdout = open(extract, 'w') 
    for i in cap:
        print(i)
    if extract:
        sys.stdout.close()

def print_packet(packet, cap, extract):
    if extract:
        sys.stdout = open(extract, 'w') 
    cap[packet].show()
    if extract:
        sys.stdout.close()

def display_length_graph(cap, extract):
    res = cap.plot(lambda x: x.len)
    if extract:
        res.save(extract)
    else:
        res.show()


def display_communication_graph(cap, extract):
    res = cap.plot(lambda x: x.src, lambda y: y.dst)
    if extract:
        res.save(extract)
    else:
        res.show()

def display_communication(cap, extract):
    d = {}
    for i in cap:
        if set(i.src, i.dst) in d:
            d[set(i.src, i.dst)][0] += 1
            d[set(i.src, i.dst)][3] += 1
            if set(i.src, i.dst)[0] == i.src:
                d[set(i.src, i.dst)][1] += len(i)
                d[set(i.src, i.dst)][4] += len(i)
            else:
                d[set(i.src, i.dst)][2] += 1
                d[set(i.src, i.dst)][5] += len(i)
        else:
            if set(i.src, i.dst)[0] == i.src:
                d[set(i.src, i.dst)] = [1, len(i), 1, len(i), 0, 0]
            else:
                d[set(i.src, i.dst)] = [1, len(i), 0, 0, 1, len(i)]
    
def check_perm():
    pass

@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.option('-l', '--list', is_flag=True, help='Print all packets')
@click.option('-s', '--short-list', is_flag=True, help='Print short info of all packets')
@click.option('-e', '--extract', default=click.Path('./autoshark_extracted'), type=click.Path(exists=True), help='Extract output to some file. Default file is ./autoshark_extracted')
@click.option('--len-graph', is_flag=True, help='Show graph by packet lenght')
@click.option('--conversations-graph', is_flag=True, help='Show graph by conversations')
@click.option('-c', '--conversations', is_flag=True, help='Print conversations info')
@click.option('-a', '--autoanalyze', type=click.Path(exists=True), help='Autoanalyze packets by yara rules. Need yara file')
@click.option('-p', '--packet', type=int, help='Show packet by number')
@click.option('-f', '--files', is_flag=True, help='Extract all files from dump')
@click.option('--agreement', is_flag = True, type = bool, default=False)
@click.argument('file', type=click.Path(exists=True), help='File to analyze')
def main(file, list, short_list, extract, len_graph, conversations_graph, conversations, autoanalyzef, packet, files, gdpr):
    if gdpr:

    if not file:
        print("Файл не выбран")
        return
    print("Считываем файл")
    try:
        cap = scapy.rdpcap(file)
    except scapy.error.Scapy_Exception:
        print("Ошибка при чтении файла. Убедитесь что файл является дампом сетевого трафика")
        return
    print(f"Считано {len(cap)} пакетов")
    if not list and not short_list and not len_graph and not conversations_graph and not conversations and not autoanalyzef and not files and not packet:
        cli(extract, cap)
    elif list and not short_list and not len_graph and not conversations_graph and not conversations and not autoanalyzef and not files and not packet:
        list_packets(cap, extract)
    elif short_list and not list and not len_graph and not conversations_graph and not conversations and not autoanalyzef and not files and not packet:
        list_short_packets(cap, extract)
    elif len_graph and not list and not short_list and not conversations_graph and not conversations and not autoanalyzef and not files and not packet:
        display_length_graph(cap, extract)
    elif conversations_graph and not list and not short_list and not len_graph and not conversations and not autoanalyzef and not files and not packet:
        display_communication_graph(cap, extract)
    elif conversations and not list and not short_list and not len_graph and not conversations_graph and not autoanalyzef and not files and not packet:
        display_communication(cap, extract)
    elif autoanalyzef and not list and not short_list and not len_graph and not conversations_graph and not conversations and not files and not packet:
        autoanalyze(cap, extract)
    elif files and not list and not short_list and not len_graph and not conversations_graph and not conversations and not autoanalyzef and not packet:
        extract_files(cap, extract)
    elif packet and not list and not short_list and not len_graph and not conversations_graph and not conversations and not autoanalyzef and not files:
        print_packet(packet, cap, extract)
    else:
        print('Выбирайте 1 задачу за запрос.')

def cli(extract, cap):
    while True:
        choose = input("""Для сохранения в файл используйте autoshark -e
Выберете действие: 
1) Вывести все пакеты
2) Вывести краткую информацию о пакетах
3) Вывести пакет
4) Вывести график по длинам пакетов (требуется графический интерфейс)
5) Вывести график по общениям между адресами (требуется графический интерфейс)
6) Вывести статистику общений между адресами
7) Извлечь все файлы из дампа
a) Автоматический анализ пакетов
>""")[0]    
        if choose == '1':
            list_packets(cap, extract)
        elif choose == '2':
            list_short_packets(cap, extract)
        elif choose == '3':
            packet = int(input("Введите номер пакета: "))
            print_packet(packet, cap, extract)
        elif choose == '4':
            display_length_graph(cap, extract)
        elif choose == '5':
            display_communication_graph(cap, extract)
        elif choose == '6':
            display_communication(cap, extract)
        elif choose == '7':
            extract_files(cap, extract)
        elif choose.lower() == 'a':
            autoanalyze(cap, extract)
        else:
            print("Неверный выбор. Пожалуйста, выберите действие из списка.")



if __name__ == '__main__':
    cli()
