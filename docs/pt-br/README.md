# Visualizador de Regras do Pfsense

- [Home](/)

Esse é um projeto com o objeto de tornar fácil o entendimento de backups do Pfsense. Essa é uma tarefa comum em ambientes legados que não possuem o engenheiro inicial presente para explicar como a estrutura foi feita.

## Objetivos Principais

- [x] Criar um parser do backup em XML do Pfsense
    - Isso foi ok de ser feito visto que foi usado o [*zek*](https://github.com/miku/zek) para criar os _structs_ do GO para representar a estrutura do arquivo.
- [ ] Gerar um diagrama usando [Terrastruct D2 Lang](https://github.com/terrastruct/d2)
    - Essa foi a razão inicial para se fazer isso
- [ ] Criar um IU usando [BubbleTea](https://github.com/charmbracelet/bubbletea)
    - Isso não é necessariamente necessário, mas é algo legal de ter.
    - É uma boa coisa para poder movimentar pelos dados. 
