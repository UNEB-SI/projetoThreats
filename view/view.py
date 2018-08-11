from tkinter import filedialog
from tkinter import *
import tkinter as tk
import pandas as pd
from sklearn import preprocessing
from sklearn.cluster import KMeans
import matplotlib.pyplot as plt

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
                    'Receive Time': df['Receive Time'],
                    'Generate Time': df['Generate Time'],
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
                     'Application': df['Application'],
                     'Direction': df['Direction'],
                     'Session ID': df['Session ID'],
                     'Repeat Count': df['Repeat Count']
                }

                arquivoOutput = 'C:/Users/Teste/Desktop/10 semestre/tcc2/Arquivos de Logs/Arquivos de Logs/Ameaças/Novos/ameacaCSV.csv'
                stringP = pd.DataFrame(results, columns = ['Receive Time', 'Generate Time','Source Address', 'Destination Address',
                                        'Source Zone', 'Destination Zone', 'Destination Port', 'Threat/Content Name', 'Severity',
                                        'thr_category', 'Destination User', 'Source User', 'Rule', 'Application', 'Direction',
                                        'Session ID', 'Repeat Count'])

                stringP.to_csv(arquivoOutput)
                self.padronizarDados(stringP, 'ameaca')

            else:
                results = {
                    'Receive Time': df['Receive Time'],
                    'Generate Time': df['Generate Time'],
                    'Source Address': df['Source address'],
                    'Destination Address': df['Destination address'],
                    'Source Zone': df['Source Zone'],
                    'Destination Zone': df['Destination Zone'],
                    'Destination Port': df['Destination Port'],
                    'Destination User': df['Destination User'],
                    'Source User': df['Source User'],
                    'Rule': df['Rule'],
                    'Threat/Content Type': df['Threat/Content Type'],
                    'session_end_reason': df['session_end_reason'],
                    'Application': df['Application'],
                    'Session ID': df['Session ID'],
                    'Repeat Count': df['Repeat Count'],
                    'Action': df['Action'],
                    'IP Protocol': df['IP Protocol'],
                    'action_source': df['action_source'],
                    'pkts_received': df['pkts_received'],
                    'pkts_sent': df['pkts_sent']
                }

                arquivoOutput = 'C:/Users/Teste/Desktop/10 semestre/tcc2/Arquivos de Logs/Arquivos de Logs/Tráfego/Novos/trafegoCSV.csv'
                stringP = pd.DataFrame(results, columns=['Receive Time', 'Generate Time','Source Address', 'Destination Address', 'Source Zone',
                                                        'Destination Zone','Destination Port', 'Destination User', 'Source User', 'Rule',
                                                        'Threat/Content Type','session_end_reason', 'Application', 'Session ID','Repeat Count',
                                                        'Action', 'IP Protocol', 'action_source', 'pkts_received', 'pkts_sent'])

                stringP.to_csv(arquivoOutput)
                self.padronizarDados(stringP, 'trafego')

    def About(self):
        print("This is a simple example of a menu")

    def metodoElbow(self, x):
        wcss = []
        for i in range(1, 11):
            kmeans = KMeans(n_clusters=i, init='random')
            kmeans.fit(x)
            print(i, kmeans.inertia_)
            wcss.append(kmeans.inertia_)


        plt.plot(range(1, 11), wcss)
        plt.title('O Metodo Elbow')
        plt.xlabel('Numero de Clusters')
        plt.ylabel('WSS')  # within cluster sum of squares
        plt.show()

    def encontrarSimilaridade(self, k, dadosTransformados, tipo):
        if tipo == 'ameaca':
            kmeans = KMeans(n_clusters=k, init='random')
            title = 'Threat'
        else:
            kmeans = KMeans(n_clusters=k, init='random')
            title = 'Traffic'

        kmeans.fit(dadosTransformados)
        plt.scatter(dadosTransformados[:, 0], dadosTransformados[:, 1], s=100, c=kmeans.labels_)
        plt.scatter(kmeans.cluster_centers_[:, 0], kmeans.cluster_centers_[:, 1], s=300, c='red', label='Centroids')
        plt.title(title + ' Clusters and Centroids')
        plt.xlabel('SepalLength')
        plt.ylabel('SepalWidth')
        plt.legend()
        plt.show()

    def padronizarDados(self, file, tipo):
        if tipo == 'ameaca':
            dadosNaoRotulados = file[['Destination Port', 'Session ID', 'Repeat Count']]
            scaler = preprocessing.StandardScaler()
            scaler.fit(dadosNaoRotulados)
            dadosTransformados = scaler.transform(dadosNaoRotulados)

            '''self.metodoElbow(dadosTranformados)'''
            k = 4
            self.encontrarSimilaridade(k,dadosTransformados, 'ameaca')
        else:
            dadosNaoRotulados = file[['Destination Port', 'Session ID', 'Repeat Count', 'pkts_received', 'pkts_sent']]
            scaler = preprocessing.StandardScaler()
            scaler.fit(dadosNaoRotulados)
            dadosTransformados = scaler.transform(dadosNaoRotulados)

            #self.metodoElbow(dadosTranformados)
            k = 4
            self.encontrarSimilaridade(k, dadosTransformados, 'trafego')

root = Tk()
View(root)

root.mainloop()