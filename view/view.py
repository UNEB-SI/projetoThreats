from tkinter import filedialog
from tkinter import *
import tkinter as tk
import pandas as pd
import csv
from pandas.io.json import json

from json import *

class View(object):

    def __init__(self, master = None):
        self.root = master
        self.root.title('Correlação de Evento e Análise de Vulnerabilidade')
        self.root.geometry('1000x1000+200+20')
        descricao = Label(self.root,
                          text="Projeto de pesquisa para conclusão do curso de sistema de informação")  # cria um label com o texto especificado
        descricao.pack()
        self.menu()


    def menu(self):

        menu = tk.Menu(self.root)


        #filemenu = Menu(menu)
        filemenu = tk.Menu(menu, tearoff=0)
        #filemenu.add_command(label="Sair", command=self.root.quit)
        # menu.add_cascade(label="Arquivo", menu=filemenu)

        # menu.add_cascade(label="File", menu=filemenu)
        filemenu.add_command(label="New", command=self.NewFile)
        filemenu.add_command(label="Open", command=self.OpenFile)
        filemenu.add_command(label="About", command=self.About)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.root.quit)
        menu.add_cascade(label="File", menu=filemenu)

        self.root.config(menu=menu)

        '''helpmenu = Menu(menu)
        menu.add_cascade(label="Help", menu=helpmenu)
        helpmenu.add_command(label="About...", command=About)'''


        # root['bg'] = 'nome da cor'

    def NewFile(self):
        print("New File!")

    def OpenFile(self):
        nomeArquivo = filedialog.askopenfilename(initialdir="", title="Select file", filetypes=[("all files", ".*")])
        with open(nomeArquivo, 'r', encoding='utf-8') as arquivo:
            df = pd.read_csv(arquivo)

            if(df['Type'][0] == "THREAT"):

                results = {
                    'Source Address': df['Source address'],
                     'Destination Address': df['Destination address'],
                     'Source Zone': df['Source Zone'],
                     'Destination Zone':df['Destination Zone'] ,
                     'Destination Port':df['Destination Port'],
                     'Threat/Content Name': df['Threat/Content Name'],
                     'Severity': df['Severity'],
                     'thr_category': df['thr_category'],
                     'Destination User': df['Destination User'],
                     'Source User': df['Source User'],
                     'Rule': df['Rule'],
                     'Receive Time': df['Receive Time'],
                     'Generate Time': df['Generate Time'],
                     'Application': df['Application'],
                     'Direction': df['Direction'],
                     'Session ID': df['Session ID'],
                     'Repeat Count': df['Repeat Count']
                }

                arquivoOutput = 'C:/Users/Teste/Desktop/10 semestre/tcc2/Arquivos de Logs/Arquivos de Logs/Ameaças/Novos/ameacaCSV.csv'
                stringP = pd.DataFrame(results, columns = ['Source Address', 'Destination Address', 'Source Zone', 'Destination Zone',
                                         'Destination Port', 'Threat/Content Name', 'Severity', 'thr_category',
                                         'Destination User', 'SourceUser', 'Rule', 'Receive Time', 'Generate Time',
                                         'Application', 'Direction', 'Session ID', 'Repeat Count'])

                stringP.to_csv(arquivoOutput)
                exit()

            else:
                results = {
                    'Source Address': df['Source address'],
                    'Destination Address': df['Destination address'],
                    'Source Zone': df['Source Zone'],
                    'Destination Zone': df['Destination Zone'],
                    'Destination Port': df['Destination Port'],
                    'Threat/Content Name': df['Threat/Content Name'],
                    'Severity': df['Severity'],
                    'thr_category': df['thr_category'],
                    'Destination User': df['Destination User'],
                    'Source User': df['Source User'],
                    'Rule': df['Rule'],
                    'Receive Time': df['Receive Time'],
                    'Generate Time': df['Generate Time'],
                    'Application': df['Application'],
                    'Direction': df['Direction'],
                    'Session ID': df['Session ID'],
                    'Repeat Count': df['Repeat Count']
                }

                arquivoOutput = 'C:/Users/Teste/Desktop/10 semestre/tcc2/Arquivos de Logs/Arquivos de Logs/Ameaças/Novos/ameacaCSV.csv'
                stringP = pd.DataFrame(results, columns=['Source Address', 'Destination Address', 'Source Zone',
                                                         'Destination Zone',
                                                         'Destination Port', 'Threat/Content Name', 'Severity',
                                                         'thr_category',
                                                         'Destination User', 'SourceUser', 'Rule', 'Receive Time',
                                                         'Generate Time',
                                                         'Application', 'Direction', 'Session ID', 'Repeat Count'])

                stringP.to_csv(arquivoOutput)
                exit()

    def About(self):
        print("This is a simple example of a menu")


root = Tk()
View(root)

root.mainloop()

