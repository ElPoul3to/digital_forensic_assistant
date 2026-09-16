# Figures

`architecture.tex` / `architecture-body.tex` — system architecture, drawn in TikZ.

Build the standalone PDF (vector, what you want in a slide deck):

```bash
cd docs/figures && pdflatex architecture.tex        # -> architecture.pdf
convert -density 300 architecture.pdf architecture.png   # optional raster export
```

Use in beamer, either as an image:

```latex
\begin{frame}{Architecture}
  \centering
  \includegraphics[width=\textwidth,height=0.85\textheight,keepaspectratio]{figures/architecture.pdf}
\end{frame}
```

or natively, so fonts and colours follow the theme and single boxes can be highlighted
with overlays (needs `\usepackage{tikz}` and
`\usetikzlibrary{positioning,fit,arrows.meta,calc,backgrounds,shapes.geometric}` in the preamble):

```latex
\begin{frame}{Architecture}
  \centering
  \resizebox{\textwidth}{!}{\input{figures/architecture-body.tex}}
\end{frame}
```

Colours: blue = private evidence pipeline, red = external ATT&CK knowledge, green = query pipeline,
purple = storage. Edit the text inside the `\node` commands to adapt labels.
