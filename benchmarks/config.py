
# Contains global configurations for the benchmarking scripts
# Load it as needed in the benchmarking scripts with import config or from config import (dict_name)

# Dictionary mapping families to their algorithms
KEM_FAMILIES = {
    'kyber': ['qkd_kyber512', 'qkd_kyber768', 'qkd_kyber1024'],
    'mlkem': ['qkd_mlkem512', 'qkd_mlkem768', 'qkd_mlkem1024'],
    'bike': ['qkd_bikel1', 'qkd_bikel3', 'qkd_bikel5'],
    'frodo': ['qkd_frodo640aes', 'qkd_frodo640shake', 
              'qkd_frodo976aes', 'qkd_frodo976shake',
              'qkd_frodo1344aes', 'qkd_frodo1344shake'],
    'hqc': ['qkd_hqc128', 'qkd_hqc192', 'qkd_hqc256']
}

# Dictionary mapping standard KEMs to their QKD variants
KEM_COMPARISON = {
    'kyber': {
        'standard': ['kyber512', 'kyber768', 'kyber1024'],
        'qkd': ['qkd_kyber512', 'qkd_kyber768', 'qkd_kyber1024']
    },
    'mlkem': {
        'standard': ['mlkem512', 'mlkem768', 'mlkem1024'],
        'qkd': ['qkd_mlkem512', 'qkd_mlkem768', 'qkd_mlkem1024']
    },
    'bike': {
        'standard': ['bikel1', 'bikel3', 'bikel5'],
        'qkd': ['qkd_bikel1', 'qkd_bikel3', 'qkd_bikel5']
    },
    'frodo': {
        'standard': ['frodo640aes', 'frodo640shake', 'frodo976aes', 
                    'frodo976shake', 'frodo1344aes', 'frodo1344shake'],
        'qkd': ['qkd_frodo640aes', 'qkd_frodo640shake', 'qkd_frodo976aes', 
                'qkd_frodo976shake', 'qkd_frodo1344aes', 'qkd_frodo1344shake']
    },
    'hqc': {
        'standard': ['hqc128', 'hqc192', 'hqc256'],
        'qkd': ['qkd_hqc128', 'qkd_hqc192', 'qkd_hqc256']
    }
}

# Global plotting style configurations 
MATPLOTLIB_PARAMS = {
    "text.usetex": True,
    "font.family": "serif",
    "font.serif": ["Computer Modern Roman"],
    "font.size": 22
}

FONT_SIZES = {
    'fig_title': 28,     # For main figure titles
    'axes_title': 24,    # For main axes titles
    'axes_label': 24,    # For x and y labels
    'tick_label': 20,    # For tick labels
    'legend': 20,        # For legend text
    'annotation': 16     # For any additional text/annotations
}

AXES_STYLE = {
    'grid': True,
    'grid_alpha': 0.5,
    'grid_linestyle': ':',
    'grid_linewidth': 0.5,
    'grid_color': 'black',
    'major_tick_length': 10,
    'minor_tick_length': 5,
    'major_tick_width': 2,
    'minor_tick_width': 1,
    'label_pad': 10
}