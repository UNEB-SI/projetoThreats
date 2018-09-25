from tkinter import filedialog
from tkinter import *
import tkinter as tk
import pandas as pd
import os
from sklearn import preprocessing
from sklearn.cluster import KMeans
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn import tree
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
import numpy as np
from matplotlib.colors import ListedColormap
from sklearn.feature_selection import SelectFromModel
import graphviz
from kmodes.kmodes import KModes
from kmodes.kprototypes import KPrototypes
from xml.etree import ElementTree as et
from matplotlib import style


class View(object):

    def __init__(self, master=None):
        self.root = master
        self.root.title('Correlação de Evento e Análise de Vulnerabilidade')
        self.root.geometry('1000x1000+200+20')
        descricao = Label(self.root,
                          text="Projeto de pesquisa para conclusão do curso de sistema de informação")  # cria um label com o texto especificado
        descricao.pack()
        self.menu()

    def menu(self):

        menu = tk.Menu(self.root)
        # filemenu = Menu(menu)
        filemenu = tk.Menu(menu, tearoff=0)
        # filemenu.add_command(label="Sair", command=self.root.quit)
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
            # df.fillna(0, axis='columns', inplace=True)

            if (df['Type'][0] == "THREAT"):
                # df['Receive Time'] = pd.to_datetime(df['Receive Time'])
                # df['Generate Time'] = pd.to_datetime(df['Generate Time'])

                for i in range(df['Destination User'].count()):
                    destino = df['Destination User'][i]
                    origem = df['Source User'][i]

                    if type(destino) == float:
                        df.loc[i, 'Destination User'] = 'Any'

                    if type(origem) == float:
                        df.loc[i, 'Source User'] = 'Any'

                results = {
                    'Receive Time': df['Receive Time'],
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
                    'Application': df['Application'],
                    'Direction': df['Direction'],
                    'Session ID': df['Session ID'],
                    'Repeat Count': df['Repeat Count']
                }

                arquivoOutput = 'C:/Users/Teste/Desktop/10 semestre/tcc2/Arquivos de Logs/Arquivos de Logs/Ameaças/Novos/trainThreats.csv'
                stringP = pd.DataFrame(results, columns=['Receive Time', 'Source Address',
                                                         'Destination Address',
                                                         'Source Zone', 'Destination Zone', 'Destination Port',
                                                         'Threat/Content Name', 'Severity',
                                                         'thr_category', 'Destination User', 'Source User', 'Rule',
                                                         'Application', 'Direction',
                                                         'Session ID', 'Repeat Count'])

                stringP.to_csv(arquivoOutput)
                self.padronizarDados(stringP)

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

                arquivoOutput = 'C:/Users/Teste/Desktop/10 semestre/tcc2/Arquivos de Logs/Arquivos de Logs/Tráfego/Novos/trainTraffic.csv'
                stringP = pd.DataFrame(results, columns=['Receive Time', 'Generate Time', 'Source Address',
                                                         'Destination Address', 'Source Zone',
                                                         'Destination Zone', 'Destination Port', 'Destination User',
                                                         'Source User', 'Rule',
                                                         'Threat/Content Type', 'session_end_reason', 'Application',
                                                         'Session ID', 'Repeat Count',
                                                         'Action', 'IP Protocol', 'action_source', 'pkts_received',
                                                         'pkts_sent'])

                stringP.to_csv(arquivoOutput)
                self.padronizarDados(stringP, 'trafego')

    def About(self):
        print("This is a simple example of a menu")

    def plot_decision_regions(self, X, y, classifier, test_idx=None, resolution=0.02):
        # setup marker generator and color map
        markers = ('s', 'x', 'o', '^', 'v')
        colors = ('red', 'blue', 'lightgreen', 'gray', 'cyan')
        cmap = ListedColormap(colors[:len(np.unique(y))])

        # plot the decision surface
        x1_min, x1_max = X[:, 0].min() - 1, X[:, 0].max() + 1
        x2_min, x2_max = X[:, 1].min() - 1, X[:, 1].max() + 1

        xx1, xx2 = np.meshgrid(np.arange(x1_min, x1_max, resolution),
                               np.arange(x2_min, x2_max, resolution), copy=False)

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

    def classificador(self, features, classes):

        '''if tipo == 'ameaca':  # pode trabalhar somente com os dados categóricos de cada tipo de arquivo
            le = preprocessing.LabelEncoder()
            file = file.apply(le.fit_transform)
            X = file.values
            y = file.columns
            X = X.transpose()

        else:
            X = file.iloc[:, :]
            y = file.columns
            X.shape
            X = X.transpose()'''

        arq = 'C:/Users/Teste/Desktop/10 semestre/tcc2/Arquivos de Logs/Arquivos de Logs/Ameaças/teste/teste.csv'
        with open(arq, 'r', encoding='utf-8') as arquivo:
            y = pd.read_csv(arquivo, parse_dates=True)

        for i in range(y['Destination User'].count()):
            destino = y['Destination User'][i]
            origem = y['Source User'][i]

            if type(destino) == float:
                y.loc[i, 'Destination User'] = 'Any'

            if type(origem) == float:
                y.loc[i, 'Source User'] = 'Any'

        results = {
            'Receive Time': y['Receive Time'],
            'Generate Time': y['Generate Time'],
            'Source Address': y['Source address'],
            'Destination Address': y['Destination address'],
            'Source Zone': y['Source Zone'],
            'Destination Zone': y['Destination Zone'],
            'Destination Port': y['Destination Port'],
            'Threat/Content Name': y['Threat/Content Name'],
            'Severity': y['Severity'],
            'thr_category': y['thr_category'],
            'Destination User': y['Destination User'],
            'Source User': y['Source User'],
            'Rule': y['Rule'],
            'Application': y['Application'],
            'Direction': y['Direction'],
            'Session ID': y['Session ID'],
            'Repeat Count': y['Repeat Count']
        }

        arquivoOutput = 'C:/Users/Teste/Desktop/10 semestre/tcc2/Arquivos de Logs/Arquivos de Logs/Ameaças/teste/testeThreats.csv'
        stringP = pd.DataFrame(results, columns=['Receive Time', 'Generate Time', 'Source Address',
                                                 'Destination Address',
                                                 'Source Zone', 'Destination Zone', 'Destination Port',
                                                 'Threat/Content Name', 'Severity',
                                                 'thr_category', 'Destination User', 'Source User', 'Rule',
                                                 'Application', 'Direction',
                                                 'Session ID', 'Repeat Count'])

        stringP.to_csv(arquivoOutput)

        X_train, X_test, y_train, y_test = train_test_split(features, stringP, test_size=0.3, random_state=0)
        result = DecisionTreeClassifier(criterion='gini', max_depth=3, random_state=0)
        result.fit(X_train, y_train)
        result.predict(X_train)

        '''dot_data = tree.export_graphviz(result, out_file=None,
                                        feature_names=file.values,
                                        class_names=file.columns,
                                        filled=True, rounded=True,
                                        special_characters=True)
        graph = graphviz.Source(dot_data)
        graph.render("file", view=True)'''

        # result.predict(X_test)

        # prev = tree.predict(X_test)'''

        '''X_combined = np.vstack((X_train, X_test))
        y_combined = np.hstack((y_train, y_test))

        self.plot_decision_regions(X_combined, y_combined, classifier=result, test_idx=range(105, 150))

        plt.xlabel('petal length [cm]')
        plt.ylabel('petal width [cm]')
        plt.legend(loc='upper left')
        plt.show()

        export_graphviz(tree, out_file='tree.dot', feature_names=file.values)'''

    def metodoElbow(self, x):
        wcss = []
        for i in range(1, 20):
            kmeans = KMeans(n_clusters=i, init='random')
            kmeans.fit(x)
            print(i, kmeans.inertia_)
            wcss.append(kmeans.inertia_)

        plt.plot(range(1, 20), wcss)
        plt.title('O Metodo Elbow')
        plt.xlabel('Numero de Clusters')
        plt.ylabel('WSS')  # within cluster sum of squares
        plt.show()

    def encontrarSimilaridade(self, k, dadosTransformados, tipo, file):
        kmeans = KMeans(n_clusters=k, init='random')
        kmeans.fit(dadosTransformados)
        labels = kmeans.predict(dadosTransformados)

        '''clusters = {}
        n = 0
        for item in labels:
            if item in clusters:
                clusters[item].append(dadosTransformados[n])
            else:
                clusters[item] = [dadosTransformados[n]]
            n += 1

        for item in clusters:
            print("Cluster ", item)
            for i in clusters[item]:
                print(i)'''

        plt.scatter(dadosTransformados[:, 0], dadosTransformados[:, 1], c=labels, s=50, cmap='viridis')

        centers = kmeans.cluster_centers_
        plt.scatter(centers[:, 0], centers[:, 1], c='black', s=200, alpha=0.5)
        plt.show()

        # self.classificador(file, tipo)

        '''plt.scatter(dadosTransformados[:, 0], dadosTransformados[:, 1], s=100, c=kmeans.labels_)
        plt.scatter(kmeans.cluster_centers_[:, 0], kmeans.cluster_centers_[:, 1], s=300, c='black', label='Centroids')
        plt.title(tipo + ' Clusters and Centroids')
        plt.xlabel('SepalLength')
        plt.ylabel('SepalWidth')
        plt.legend()
        plt.show()'''

    def padronizarDados(self, file):
        # style.use("ggplot")
        caminho = 'C:/Users/Teste/Desktop/10 semestre/tcc2/Arquivos de Logs/Arquivos de Logs/Ameaças/Novos/trainThreats.csv'
        colors = ['b', 'orange', 'g', 'r', 'c', 'm', 'y', 'k', 'Brown', 'ForestGreen']
        # Data points with their publisher name,category score, category name, place name
        syms = np.genfromtxt(caminho, dtype=str, delimiter=',', skip_header=1)[:, 8]
        X = np.genfromtxt(caminho, dtype=object, delimiter=',', skip_header=1)[:, 1:]

        kproto = KPrototypes(n_clusters=5, init='Cao', verbose=2)
        clusters = kproto.fit_predict(X, categorical=[0, 1, 2, 3, 4, 6, 7,8, 9, 10, 11, 12, 13])

        file['clusters'] = clusters

        # Print cluster centroids of the trained model.
        print(kproto.cluster_centroids_)
        # Print training statistics
        print(kproto.cost_)
        print(kproto.n_iter_)

        for s, c in zip(syms, clusters):
            print("Result: {}, cluster:{}".format(s, c))

        my_dpi = 96
        fig = plt.figure(figsize=(800/my_dpi, 800/my_dpi), dpi=my_dpi)
        ax = fig.add_subplot(1, 1, 1)
        newClusters = []
        newSyms = []
        newClusters.append(clusters)

        le = preprocessing.LabelEncoder()
        syms_ = le.fit_transform(syms)
        newSyms.append(syms)

        scatter = ax.scatter(X[:, 0], X[:, 1], c=clusters, s=50, cmap='viridis')

        '''dadosAgrupados = zip(newSyms, newClusters)
        for data in dadosAgrupados:
            x, y = data
            scatter = ax.scatter(x, y, alpha=0.8, c=clusters, edgecolors='none', s=100)

        plt.title('K-Prototypes Clustering')
        ax.set_xlabel('Severity')
        ax.set_ylabel('Clusters')
        plt.colorbar(scatter)
        ax.set_title('Data points classifed according to known centers')
        plt.show()'''



        # Plot the results
        '''for i in set(kproto.labels_):
            index = kproto.labels_ == i
            plt.plot(X[index, 0], X[index, 1], 'o')
            plt.suptitle('Data points categorized with category score', fontsize=18)
            plt.xlabel('Category Score', fontsize=16)
            plt.ylabel('Category Type', fontsize=16)
        plt.title('Resultado K-Prototypes')
        plt.grid(True)
        plt.show()

        # Clustered result
        fig1, ax3 = plt.subplots()
        scatter = ax3.scatter(syms, clusters, c=clusters, s=50)
        ax3.set_xlabel('Data points')
        ax3.set_ylabel('Cluster')
        plt.colorbar(scatter)
        ax3.set_title('Data points classifed according to known centers')
        plt.show()

        result = zip(syms, kproto.labels_)
        sortedR = sorted(result, key=lambda x: x[1])
        print(sortedR)'''

        # self.classificador(kproto.cluster_centroids_, sortedR) #primeiro argumento serão as features e o segundo argumento serão as classes

        '''le = preprocessing.LabelEncoder()
        file = file.apply(preprocessing.LabelEncoder().fit_transform)
        scaler = preprocessing.StandardScaler()
        new = scaler.fit_transform(file)

        x = file.values
        y = file.columns

        #variaveis quantitativas nominal, pois nao precisa de uma ordem
        #teste não paramétricos (qui - quadrado)
        #features são os valores , caracterisiticas, e classes são  strings que caractreiza um valor da feature

        x = x.transpose()
        clf = ExtraTreesClassifier()
        clf.fit(x, y)
        clf.feature_importances_

        model = SelectFromModel(clf, prefit=True)
        X_new = model.transform(x)
        X_new.shape
        X_new = X_new.transpose()
        

        features = file.columns.difference(['Class'])
        print(file['Class'])
        exit()


        features_importance = zip(clf.feature_importances_, features)
        for importance, feature in sorted(features_importance):
            print("%s: %f%%" % (feature, importance * 100))

        exit()



        self.metodoElbow(new)

        k = 10
        self.encontrarSimilaridade(k,new, tipo, file)'''
        self.lerXML(file)

    def lerXML(self,file):

        file_name = "C:/Users/Teste/Desktop/Logs - PP1/running-config.xml"
        full_file = os.path.abspath(os.path.join('data', file_name))

        dom = et.parse(full_file)
        rules = dom.findall('devices/entry/vsys/entry/rulebase/security/rules')
        rulesEntry = dom.findall('devices/entry/vsys/entry/rulebase/security/rules/entry')

        self.idAmecaFalsoPositivo(file, rules, rulesEntry)

    def idAmecaFalsoPositivo(self, file, rules, rulesEntry):
        regras = []

        for entry in rules:
            for child in entry:
                regras.append(child.attrib)


        for i, item in enumerate(rulesEntry):
            regras[i]['from'] = {item.find("from/member").text}
            regras[i]['source'] = {item.find("source/member").text}
            regras[i]['destination'] = {item.find("destination/member").text}
            regras[i]['source-user'] = {item.find("source-user/member").text}
            regras[i]['category'] = {item.find("category/member").text}
            regras[i]['application'] = [item.find("application")]
            regras[i]['service'] = {item.find("service/member").text}
            regras[i]['action'] = {item.find("action").text}
            regras[i]['app'] = []

            for app in regras[i]['application']:
                for node in app.getiterator():
                    regras[i]['app'].append(node.text)

        for i in enumerate(regras):
            if(file['Rule'] == regras[i]['name']):
                if(file['Severity'] != 'critical'):
                    if((file['Application'] == regras[i]['app']) and (file['Source User'] == regras[i]['source-user'])):
                        file['False Positive'] = 'yes'
                    else:
                        file['False Positive'] = 'no'
                else:
                    file['False Positive'] = 'no'
            else:
                print('Rule does not exist')

        print(file)
        exit()

root = Tk()
View(root)

root.mainloop()
