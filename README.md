# Pfsense Rule Visualizer

- [Português](docs/pt-br/README.md)

This is a project with the objective to make easier to understand Pfsense backups. It's a common task in legacy environments that lack the original engineer to explain the structure.

## Main Objectives
- [x] Create the Pfsense backup XML parser.
    - This was ok as it was done with [*zek*](https://github.com/miku/zek) that creates a struct that represents the xml file.
- [ ] Generate a Diagram using [Terrastruct D2 Lang](https://github.com/terrastruct/d2)
    - This is/was the original main objective
- [ ] Create a UI using [BubbleTea](https://github.com/charmbracelet/bubbletea)
    - This isn't exactly necessary. But it's a nice thing to have.
    - This is a good thing to move around the data.
