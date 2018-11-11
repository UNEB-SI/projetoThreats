from tkinter import filedialog
from tkinter import *
import tkinter as tk
import pandas as pd
import os

from matplotlib import style
from sklearn import preprocessing
from sklearn.tree import DecisionTreeClassifier, export
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
import numpy as np
import graphviz
from kmodes.kprototypes import KPrototypes
from xml.etree import ElementTree as et
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import accuracy_score, confusion_matrix

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

    def NewFile(self):
        print("New File!")

    def OpenFile(self):
        arq = 'C:/Users/Teste/Desktop/10 semestre/tcc2/Arquivos de Logs/Arquivos de Logs/new.csv'
        x = pd.read_csv(arq)
        #self.ClassifierNaiveBayes(x)
        #self.ClassifierDecicionTree(x)
        #self.ClassifierKNN(x)
        self.ClassifierRegressionLogistic(x)
        nomeArquivo = filedialog.askopenfilename(initialdir="", title="Select file", filetypes=[("all files", ".*")])
        with open(nomeArquivo, 'r', encoding='utf-8') as arquivo:
            df = pd.read_csv(arquivo)

            df['Receive Time'] = pd.to_datetime(df['Receive Time'])

            for i in range(df.shape[0]):
                destino = df['Destination User'][i]
                origem = df['Source User'][i]
                enderecoOrigem = df['Source address'][i]
                enderecoDestino = df['Destination address'][i]

                if type(destino) == float:
                    df.loc[i, 'Destination User'] = 'any'

                if type(origem) == float:
                    df.loc[i, 'Source User'] = 'any'

                if type(enderecoOrigem) == float:
                    df.loc[i, 'Source address'] = 'any'

                if type(enderecoDestino) == float:
                    df.loc[i, 'Source address'] = 'any'


            results = {
                'Receive Time': df['Receive Time'],
                'Source Address': df['Source address'],
                'Destination Address': df['Destination address'],
                'Source Zone': df['Source Zone'],
                'Destination Zone': df['Destination Zone'],
                'Source Port': df['Source Port'],
                'Destination Port': df['Destination Port'],
                'Threat/Content Name': df['Threat/Content Name'],
                'Severity': df['Severity'],
                'thr_category': df['thr_category'],
                'Destination User': df['Destination User'],
                'Source User': df['Source User'],
                'Rule': df['Rule'],
                'Application': df['Application'],
                'Direction': df['Direction']
            }

            arquivoOutput = 'C:/Users/Teste/Desktop/10 semestre/tcc2/Arquivos de Logs/Arquivos de Logs/Ameaças/Novos/trainThreats.csv'
            stringP = pd.DataFrame(results, columns=['Receive Time', 'Source Address',
                                                     'Destination Address', 'Source Zone', 'Destination Zone',
                                                     'Source Port', 'Destination Port', 'Threat/Content Name',
                                                     'Severity', 'thr_category', 'Destination User', 'Source User',
                                                     'Rule', 'Application', 'Direction'])

            stringP.to_csv(arquivoOutput)
            #self.lerXML(x)
            #self.agruparDados(stringP)

    def About(self):
        print("This is a simple example of a menu")

    def metricas(self, classe_teste, previsoes):#0 no, 1 yes
        precisao = accuracy_score(classe_teste, previsoes)
        matriz = confusion_matrix(classe_teste, previsoes)

        print(precisao)
        print(matriz)

    def padronizarDados(self, file):

        le = preprocessing.LabelEncoder()
        previsores = file.iloc[:, 1:17].values #mudar pra zero dps dos testes e 16
        classes = file.iloc[:, 17].values
        classes = classes.astype(str)

        # previsores[:, 0] = le.fit_transform(previsores[:, 0])
        previsores[:, 1] = le.fit_transform(previsores[:, 1])
        previsores[:, 2] = le.fit_transform(previsores[:, 2])
        previsores[:, 3] = le.fit_transform(previsores[:, 3])
        previsores[:, 4] = le.fit_transform(previsores[:, 4])
        # previsores[:, 5] = le.fit_transform(previsores[:, 5])
        # previsores[:, 6] = le.fit_transform(previsores[:, 6])
        previsores[:, 7] = le.fit_transform(previsores[:, 7])
        previsores[:, 8] = le.fit_transform(previsores[:, 8])
        previsores[:, 9] = le.fit_transform(previsores[:, 9])
        previsores[:, 10] = le.fit_transform(previsores[:, 10].astype(str))
        previsores[:, 11] = le.fit_transform(previsores[:, 11].astype(str))
        previsores[:, 12] = le.fit_transform(previsores[:, 12])
        previsores[:, 13] = le.fit_transform(previsores[:, 13])
        previsores[:, 14] = le.fit_transform(previsores[:, 14])

        previsores[:, 0] = pd.to_datetime(previsores[:, 0]).astype('int64')
        max_a = previsores[:, 0].max()
        min_a = previsores[:, 0].min()
        min_norm = -1
        max_norm = 1
        previsores[:, 0] = (previsores[:, 0] - min_a) * (max_norm - min_norm) / (max_a - min_a) + min_norm

        scaler = preprocessing.StandardScaler()
        previsores = scaler.fit_transform(previsores)
        return previsores, classes

    def ClassifierRegressionLogistic(self, file):
        previsores, classes = self.padronizarDados(file)
        resultados30 = []
        for i in range(30):
            kfold = StratifiedKFold(n_splits=10, shuffle=True, random_state=i)
            resultados1 = []
            for indice_treinamento, indice_teste in kfold.split(previsores, np.zeros(shape=(classes.shape[0], 1))):
                classificador = LogisticRegression()
                classificador.fit(previsores[indice_treinamento], classes[indice_treinamento])
                previsoes = classificador.predict(previsores[indice_teste])
                precisao = accuracy_score(classes[indice_teste], previsoes)
                resultados1.append(precisao)

            resultados1 = np.asarray(resultados1)
            media = resultados1.mean()
            resultados30.append(media)

        resultados30 = np.asarray(resultados30)
        resultados30.mean()
        for i in range(resultados30.size):
            print(str(resultados30[i]).replace('.', ','))
        exit()

    def ClassifierKNN(self, file):
        previsores, classes = self.padronizarDados(file)
        resultados30 = []
        for i in range(30):
            kfold = StratifiedKFold(n_splits=10, shuffle=True, random_state=i)
            resultados1 = []
            for indice_treinamento, indice_teste in kfold.split(previsores, np.zeros(shape=(classes.shape[0], 1))):
                classificador = KNeighborsClassifier(metric='minkowski', p=2)
                classificador.fit(previsores[indice_treinamento], classes[indice_treinamento])
                previsoes = classificador.predict(previsores[indice_teste])
                precisao = accuracy_score(classes[indice_teste], previsoes)
                resultados1.append(precisao)

            resultados1 = np.asarray(resultados1)
            media = resultados1.mean()
            resultados30.append(media)

        resultados30 = np.asarray(resultados30)
        resultados30.mean()
        for i in range(resultados30.size):
            print(str(resultados30[i]).replace('.', ','))
        exit()

    def ClassifierNaiveBayes(self, file):
        previsores, classes = self.padronizarDados(file)
        resultados30 = []
        for i in range(30):
            kfold = StratifiedKFold(n_splits=10, shuffle=True, random_state=i)
            resultados1 = []
            for indice_treinamento, indice_teste in kfold.split(previsores, np.zeros(shape=(classes.shape[0], 1))):
                classificador = GaussianNB()
                classificador.fit(previsores[indice_treinamento], classes[indice_treinamento])
                previsoes = classificador.predict(previsores[indice_teste])
                precisao = accuracy_score(classes[indice_teste], previsoes)
                resultados1.append(precisao)

            resultados1 = np.asarray(resultados1)
            media = resultados1.mean()
            resultados30.append(media)

        resultados30 = np.asarray(resultados30)
        resultados30.mean()
        for i in range(resultados30.size):
            print(str(resultados30[i]).replace('.', ','))
        exit()

    def ClassifierDecicionTree(self, file):

        previsores, classes = self.padronizarDados(file)
        resultados30 = []
        for i in range(30):
            kfold = StratifiedKFold(n_splits=10, shuffle=True, random_state=i)
            resultados1 = []
            for indice_treinamento, indice_teste in kfold.split(previsores, np.zeros(shape=(classes.shape[0], 1))):
                classificador = DecisionTreeClassifier(criterion='entropy', random_state=0)
                classificador.fit(previsores[indice_treinamento], classes[indice_treinamento])
                previsoes = classificador.predict(previsores[indice_teste])
                precisao = accuracy_score(classes[indice_teste], previsoes)
                resultados1.append(precisao)

            resultados1 = np.asarray(resultados1)
            media = resultados1.mean()
            resultados30.append(media)

        resultados30 = np.asarray(resultados30)
        resultados30.mean()
        for i in range(resultados30.size):
            print(str(resultados30[i]).replace('.', ','))
        exit()
        '''dot_data = export.export_graphviz(classificador,
                                          out_file=None,
                                          feature_names=['Receive Time','Source Address',
                                                         'Destination Address',
                                                         'Source Zone', 'Destination Zone',
                                                         'Source Port', 'Destination Port',
                                                         'Threat/Content Name', 'Severity',
                                                         'thr_category', 'Destination User', 'Source User', 'Rule',
                                                         'Application', 'Direction', 'Clusters'],
                                          class_names=classes,
                                          filled=True, rounded=True,
                                          leaves_parallel=True,
                                          special_characters=True)
        graph = graphviz.Source(dot_data)
        graph.render("file", view=True)'''
        exit()

    def agruparDados(self, file):

        style.use("ggplot")
        caminho = 'C:/Users/Teste/Desktop/10 semestre/tcc2/Arquivos de Logs/Arquivos de Logs/Ameaças/Novos/trainThreats.csv'
        colors = ['b', 'orange', 'g', 'r', 'c', 'm', 'y', 'k', 'Brown', 'ForestGreen']
        # Data points with their publisher name,category score, category name, place name
        #category = np.genfromtxt(caminho, dtype=str, delimiter=',', skip_header=1)[:, 9]  # categoria
        #severity = np.genfromtxt(caminho, dtype=str, delimiter=',', skip_header=1)[:, 8]  # severidade
        X = np.genfromtxt(caminho, dtype=object, delimiter=',', skip_header=1)[:, 1:]

        kproto = KPrototypes(n_clusters=4, init='Cao', verbose=2)
        clusters = kproto.fit_predict(X, categorical=[0, 1, 2, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14])

        file['Clusters'] = clusters

        # Print cluster centroids of the trained model.
        print(kproto.cluster_centroids_)
        # Print training statistics
        print(kproto.cost_)
        print(kproto.n_iter_)
        print(kproto.gamma)

        '''plt.scatter(X[clusters == 0, 8], X[clusters == 0, 9], c='purple', alpha=0.5, s=150,  label='Cluster 0')
        plt.scatter(X[clusters == 1, 8], X[clusters == 1, 9], c='black', alpha=0.5, s=150,  label='Cluster 1')
        plt.scatter(X[clusters == 2, 8], X[clusters == 2, 9], c='red', alpha=0.5, s=150,  label='Cluster 2')
        plt.scatter(X[clusters == 3, 8], X[clusters == 3, 9], c='green', alpha=0.5, s=150,  label='Cluster 3')
        plt.scatter(X[clusters == 4, 8], X[clusters == 4, 9], c='blue', alpha=0.5, s=100, label='Cluster 4')
        plt.scatter(X[clusters == 5, 8], X[clusters == 5, 9], c='yellow', alpha=0.5, s=100, label='Cluster 5')
        plt.xlabel('Severity')
        plt.ylabel('Category')
        plt.legend()
        plt.show()'''

        self.lerXML(file)

    def lerXML(self, file):

        file_name = "C:/Users/Teste/Desktop/10 semestre/tcc2/Arquivos de Logs/Arquivos de Logs/Ameaças/unib/running-config.xml"
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
            regras[i]['to'] = [item.find("to")]
            regras[i]['from'] = [item.find("from")]
            regras[i]['source'] = [item.find("source")]
            regras[i]['destination'] = [item.find("destination")]
            regras[i]['source-user'] = [item.find("source-user")]
            regras[i]['category'] = [item.find("category")]
            regras[i]['application'] = [item.find("application")]
            regras[i]['service'] = [item.find("service")]
            regras[i]['action'] = [item.find("action")]
            regras[i]['to_'] = []
            regras[i]['from_'] = []
            regras[i]['source_'] = []
            regras[i]['destination_'] = []
            regras[i]['source-user_'] = []
            regras[i]['category_'] = []
            regras[i]['application_'] = []
            regras[i]['service_'] = []

            for to in regras[i]['to']:
                for node1 in to.getiterator():
                    regras[i]['to_'].append(node1.text)

            for from_ in regras[i]['from']:
                for node2 in from_.getiterator():
                    regras[i]['from_'].append(node2.text)

            for source in regras[i]['source']:
                for node3 in source.getiterator():
                    regras[i]['source_'].append(node3.text)

            for destination in regras[i]['destination']:
                for node4 in destination.getiterator():
                    regras[i]['destination_'].append(node4.text)

            for source_user in regras[i]['source-user']:
                for node5 in source_user.getiterator():
                    regras[i]['source-user_'].append(node5.text)

            for category in regras[i]['category']:
                for node6 in category.getiterator():
                    regras[i]['category_'].append(node6.text)

            for app in regras[i]['application']:
                for node7 in app.getiterator():
                    regras[i]['application_'].append(node7.text)

            for service in regras[i]['service']:
                for node8 in service.getiterator():
                    regras[i]['service_'].append(node8.text)

        tamRegras = len(regras)
        for index, row in file.iterrows():
            for i in range(tamRegras):
                if row["Rule"] == regras[i]['name']:
                    if row["Severity"] != "critical" : #and row["Severity"] != "high"
                        if ((row["Source Zone"] != "CORPORATIVA") and (row['Destination Zone'] == "CORPORATIVA") and
                                (row["Application"] in regras[i]['application_'])):
                            file.loc[index, 'False Positive'] = 'yes'
                        elif((row["Source Zone"] != "CORPORATIVA") and (row['Destination Zone'] != "CORPORATIVA") and
                                (row["Application"] in regras[i]['application_'])):
                            file.loc[index, 'False Positive'] = 'yes'
                        else:
                            file.loc[index, 'False Positive'] = 'no'
                        if((row['Source User'] in regras[i]['source-user_']) and (row["Source Address"] != "any") and
                                (row['Destination Address'] != "any")):
                            file.loc[index, 'False Positive'] = 'yes' #equivale a sim
                        else:
                            file.loc[index, 'False Positive'] = 'no'
                    else:
                        file.loc[index, 'False Positive'] = 'no' #equivale a nao

        arquivoOutput = 'C:/Users/Teste/Desktop/10 semestre/tcc2/Arquivos de Logs/Arquivos de Logs/new.csv'
        file.to_csv(arquivoOutput)
        self.ClassifierNaiveBayes(file)
        #self.ClassifierDecicionTree(file)
        #self.ClassifierKNN(file)


root = Tk()
View(root)

root.mainloop()