"""The demos. Each one is a package so that four modules called
`make_vector` can live in one process: the driver imports
`demos.<demo>.host.replay`, and a bare `import make_vector` would hand the
second demo the first demo's module. That is the same sys.path trap that the
repository's own notes keep warning about, and it showed up here as a missing
array name rather than as an import error.
"""
