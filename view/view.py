from tkinter import filedialog
from tkinter import *
import tkinter as tk
import pandas as pd
from sklearn import preprocessing
from sklearn.cluster import KMeans
from sklearn import tree
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
import numpy as np
from matplotlib.colors import ListedColormap
from sklearn.tree import export_graphviz


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
            count = df['Destination User'].count()

            if(df['Type'][0] == "THREAT"):
                for i in range(count):
                    destino =df['Destination User'][i]
                    origem =df['Source User'][i]

                    if type(destino) == float:
                        df.loc[i, 'Destination User'] = 'Local User'

                    if type(origem) == float:
                        df.loc[i, 'Source User'] = 'Local User'

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

    def plot_decision_regions(self,X, y, classifier, test_idx=None, resolution=0.02):
        # setup marker generator and color map
        markers = ('s', 'x', 'o', '^', 'v')
        colors = ('red', 'blue', 'lightgreen', 'gray', 'cyan')
        cmap = ListedColormap(colors[:len(np.unique(y))])

        # plot the decision surface
        x1_min, x1_max = X[:, 0].min() - 1, X[:, 0].max() + 1
        x2_min, x2_max = X[:, 1].min() - 1, X[:, 1].max() + 1
        xx1, xx2 = np.meshgrid(np.arange(x1_min, x1_max, resolution),
                               np.arange(x2_min, x2_max, resolution))
        Z = classifier.predict(np.array([xx1.ravel(), xx2.ravel()]).T)
        Z = Z.reshape(xx1.shape)
        plt.contourf(xx1, xx2, Z, alpha=0.4, cmap=cmap)
        plt.xlim(xx1.min(), xx1.max())
        plt.ylim(xx2.min(), xx2.max())

        # plot all samples
        X_test, y_test = X[test_idx, :], y[test_idx]
        for idx, cl in enumerate(np.unique(y)):
            plt.scatter(x=X[y == cl, 0], y=X[y == cl, 1],
                        alpha=0.8, c=cmap(idx),
                        marker=markers[idx], label=cl)
        # highlight test samples
        if test_idx:
            X_test, y_test = X[test_idx, :], y[test_idx]
            plt.scatter(X_test[:, 0], X_test[:, 1], c='',
                        alpha=1.0, linewidth=1, marker='o',
                        s=55, label='test set')


    def classificador(self, file, tipo):

        if tipo == 'ameaca':
            X = file.iloc[:, [2, 3]]
            y = file.columns

        else:
            X = file.iloc[:, [2, 3]]
            y = file.columns

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=0)
        tree = DecisionTreeClassifier(criterion='entropy',
                                      max_depth=3, random_state=0)

        print(tree)
        exit()
        tree.fit(X_train, y_train)

        X_combined = np.vstack((X_train, X_test))
        y_combined = np.hstack((y_train, y_test))



        self.plot_decision_regions(X_combined, y_combined,
                              classifier=tree, test_idx=range(105, 150))

        plt.xlabel('petal length [cm]')
        plt.ylabel('petal width [cm]')
        plt.legend(loc='upper left')
        plt.show()

        export_graphviz(tree,
                        out_file='tree.dot',
                        feature_names=['petal length', 'petal width'])



    def metodoElbow(self, x):
        wcss = []
        for i in range(1, 30):
            kmeans = KMeans(n_clusters=i, init='random')
            kmeans.fit(x)
            print(i, kmeans.inertia_)
            wcss.append(kmeans.inertia_)

        plt.plot(range(1, 30), wcss)
        plt.title('O Metodo Elbow')
        plt.xlabel('Numero de Clusters')
        plt.ylabel('WSS')  # within cluster sum of squares
        plt.show()

    def encontrarSimilaridade(self, k, dadosTransformados, tipo, file):
        if tipo == 'ameaca':
            kmeans = KMeans(n_clusters=k, init='random')
            title = 'Threat'
        else:
            kmeans = KMeans(n_clusters=k, init='random')
            title = 'Traffic'

        kmeans.fit(dadosTransformados)
        labels = kmeans.predict(dadosTransformados)
        clusters = {}
        n = 0
        for item in labels:
            if item in clusters:
                clusters[item].append(dadosTransformados[n])
            else:
                clusters[item] = [dadosTransformados[n]]
            n += 1

        '''for item in clusters:
            print("Cluster ", item)
            for i in clusters[item]:
                print(i)'''

        self.classificador(file, 'ameaca')

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

            ''' self.metodoElbow(dadosTransformados)'''
            k = 6
            self.encontrarSimilaridade(k,dadosTransformados, 'ameaca', file)
        else:
            dadosNaoRotulados = file[['Destination Port', 'Session ID', 'Repeat Count', 'pkts_received', 'pkts_sent']]
            scaler = preprocessing.StandardScaler()
            scaler.fit(dadosNaoRotulados)
            dadosTransformados = scaler.transform(dadosNaoRotulados)

            #self.metodoElbow(dadosTranformados)
            '''k = 4
            self.encontrarSimilaridade(k, dadosTransformados, 'trafego')'''

root = Tk()
View(root)

root.mainloop()