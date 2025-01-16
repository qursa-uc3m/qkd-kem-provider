import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
from matplotlib.ticker import AutoMinorLocator, MultipleLocator
import os

from config import (KEM_FAMILIES, KEM_COMPARISON, 
                    FONT_SIZES, AXES_STYLE)

# -- -- DATA PROCESSING -- -- #

def kem_data_process(csv_path):
    """
    Reads a CSV file and filters for KEM algorithms with 'qkd_' prefix.
    Adds a TotalTime column that sums KeyGen, Encaps, and Decaps times.
    
    Args:
        csv_path (str): Path to the CSV file
        
    Returns:
        pd.DataFrame: Filtered DataFrame with added TotalTime column
    """
    # Read CSV file
    df = pd.read_csv(csv_path)
    
    # Filter for algorithms with 'qkd_' prefix
    qkd_mask = df['Algorithm'].str.startswith('qkd_')
    filtered_df = df[qkd_mask].copy()
    
    # Add TotalTime column (sum of KeyGen, Encaps, and Decaps times)
    filtered_df['TotalTime(ms)'] = (filtered_df['KeyGen(ms)'] + 
                               filtered_df['Encaps(ms)'] + 
                               filtered_df['Decaps(ms)'])
    
    return filtered_df

def load_comparison_data(csv_path):
    """
    Reads a CSV file and filters for both standard and QKD versions of main KEM families.
    
    Args:
        csv_path (str): Path to the CSV file
        
    Returns:
        pd.DataFrame: Filtered DataFrame with added TotalTime column
    """
    # Read CSV file
    df = pd.read_csv(csv_path)
    
    # Get all algorithms we want to compare
    algorithms_to_keep = []
    for family in KEM_COMPARISON.values():
        algorithms_to_keep.extend(family['standard'])
        algorithms_to_keep.extend(family['qkd'])
    
    # Filter for our algorithms of interest
    filtered_df = df[df['Algorithm'].isin(algorithms_to_keep)].copy()
    
    # Add TotalTime column
    filtered_df['TotalTime'] = (filtered_df['KeyGen(ms)'] + 
                               filtered_df['Encaps(ms)'] + 
                               filtered_df['Decaps(ms)'])
    
    return filtered_df

def kem_data_summary(df, warmup=3):
    """
    Generates summary statistics for each algorithm in the DataFrame, excluding warmup iterations.
    
    Args:
        df (pd.DataFrame): Input DataFrame with KEM measurements
        warmup (int): Number of initial iterations to exclude (default: 3)
        
    Returns:
        pd.DataFrame: Summary statistics DataFrame with columns for count, mean, std, min, max
    """
    # Filter out warmup iterations
    df_filtered = df[df['Iteration'] > warmup]
    
    # Group by Algorithm and calculate statistics
    summary_stats = df_filtered.groupby('Algorithm').agg({
        'Iteration': 'count',
        'KeyGen(ms)': ['mean', 'std', 'min', 'max'],
        'Encaps(ms)': ['mean', 'std', 'min', 'max'],
        'Decaps(ms)': ['mean', 'std', 'min', 'max'],
        'TotalTime(ms)': ['mean', 'std', 'min', 'max']
    }).round(3)
    
    # Flatten column names
    summary_stats.columns = [
        f'{col[0]}_{col[1]}' if col[1] else col[0] 
        for col in summary_stats.columns
    ]
    
    # Rename count column
    summary_stats = summary_stats.rename(columns={'Iteration_count': 'NumIterations'})
    
    return summary_stats

def compute_ops_percent(df):
    """
    Calculates the percentage contribution of each operation to total time.
    
    Args:
        df: DataFrame with mean operation times
        
    Returns:
        DataFrame with operation percentages
    """
    # Calculate percentages
    ops = ['KeyGen(ms)_mean', 'Encaps(ms)_mean', 'Decaps(ms)_mean']
    percentages = df[ops].copy()
    
    # Convert to percentages
    total = percentages.sum(axis=1)
    for col in ops:
        percentages[col] = (percentages[col] / total) * 100
        
    return percentages

def generate_comparison_stats(df):
    """
    Generates summary statistics for comparative analysis.
    
    Args:
        df (pd.DataFrame): Input DataFrame from load_comparison_data
        
    Returns:
        pd.DataFrame: Summary statistics DataFrame
    """
    # Group by Algorithm and calculate statistics
    summary_stats = df.groupby('Algorithm').agg({
        'Iteration': 'count',
        'KeyGen(ms)': ['mean', 'std', 'min', 'max'],
        'Encaps(ms)': ['mean', 'std', 'min', 'max'],
        'Decaps(ms)': ['mean', 'std', 'min', 'max'],
        'TotalTime': ['mean', 'std', 'min', 'max']
    }).round(3)
    
    # Flatten column names
    summary_stats.columns = [
        f'{col[0]}_{col[1]}' if col[1] else col[0] 
        for col in summary_stats.columns
    ]
    
    # Rename count column
    summary_stats = summary_stats.rename(columns={'Iteration_count': 'NumIterations'})
    
    return summary_stats

# -- -- DATA PLOTTING -- -- #

def apply_axes_style(ax, xlabel=None, ylabel=None, title=None):
    """
    Applies consistent styling to plot axes.
    
    Args:
        ax: matplotlib axes object
        xlabel: x-axis label (optional)
        ylabel: y-axis label (optional)
        title: plot title (optional)
    """
    # Set labels and title if provided
    if xlabel:
        ax.set_xlabel(r'\textbf{' + xlabel + '}', 
                     fontsize=FONT_SIZES['axes_label'], 
                     labelpad=AXES_STYLE['label_pad'])
    if ylabel:
        ax.set_ylabel(r'\textbf{' + ylabel + '}', 
                     fontsize=FONT_SIZES['axes_label'], 
                     labelpad=AXES_STYLE['label_pad'])
    if title:
        ax.set_title(title, 
                    fontsize=FONT_SIZES['axes_title'], 
                    pad=20)

    # Configure grid
    ax.grid(AXES_STYLE['grid'], 
            alpha=AXES_STYLE['grid_alpha'], 
            zorder=0)
    ax.grid(which='minor', 
            color=AXES_STYLE['grid_color'],
            linestyle=AXES_STYLE['grid_linestyle'], 
            linewidth=AXES_STYLE['grid_linewidth'], 
            alpha=0.3)

    # Configure ticks
    ax.tick_params(axis='both', 
                  which='major',
                  length=AXES_STYLE['major_tick_length'],
                  width=AXES_STYLE['major_tick_width'],
                  labelsize=FONT_SIZES['tick_label'])
    ax.tick_params(axis='both', 
                  which='minor',
                  length=AXES_STYLE['minor_tick_length'],
                  width=AXES_STYLE['minor_tick_width'])

    # Add minor ticks
    ax.yaxis.set_minor_locator(AutoMinorLocator())
    if not ax.get_xscale() == 'log':
        ax.xaxis.set_minor_locator(AutoMinorLocator())

def plot_kem_times(input_df, error_suffix="_std", plot_title="kem_times.png", y_start=None):
    """
    Plots KEM timing measurements (KeyGen, Encaps, Decaps) for different algorithms.
    
    Args:
        input_df: DataFrame containing the KEM timing data
        error_suffix: Suffix for error columns (default: "_std")
        plot_title: Output filename for the plot
        y_start: Starting point for y-axis (optional)
    """
    
    # Sort algorithms by total time
    input_df = input_df.sort_values('TotalTime(ms)_mean')
    
    # Setup plot dimensions
    width = 0.25  # width of the bars
    algorithms = input_df.index.tolist()  # algorithms are in the index
    x = np.arange(len(algorithms))  # label locations
    
    # Create color palette for the three operations
    colors = list(mcolors.LinearSegmentedColormap.from_list("", ["#9fcf69", "#33acdc"])(np.linspace(0, 1, 3)))
    
    # Create figure and axis
    fig, ax = plt.subplots(figsize=(20, 10))
    
    # Plot bars for each operation
    operations = ['KeyGen(ms)', 'Encaps(ms)', 'Decaps(ms)']
    bars = []
    for i, (operation, color) in enumerate(zip(operations, colors)):
        mean_col = f"{operation}_mean"
        std_col = f"{operation}{error_suffix}"
        
        container = ax.bar(x + (i-1)*width, 
                         input_df[mean_col],
                         width,
                         label=operation.replace('(ms)', ''),
                         color=color,
                         edgecolor='black',
                         linewidth=1,
                         yerr=input_df[std_col],
                         capsize=3,
                         error_kw={'ecolor': 'black'},
                         zorder=3)
        
        # Style error bars
        if error_suffix:
            for line in container.errorbar.lines[2]:
                line.set_linestyle('dashed')
                line.set_linewidth(0.75)
        
        bars.append(container)
    
    # Apply consistent styling
    apply_axes_style(ax, 
                    xlabel='Algorithm',
                    ylabel='Time (ms)')
    
    # Set x-ticks with LaTeX formatting for underscores
    ax.set_xticks(x)
    ax.set_xticklabels([alg.replace('_', '\_') for alg in algorithms], 
                       rotation=45, 
                       horizontalalignment='right',
                       fontsize=FONT_SIZES['tick_label'])
    
    # Set major and minor tick locators
    # # ax.yaxis.set_major_locator(MultipleLocator())  # Major ticks every 2 units
    ax.yaxis.set_minor_locator(AutoMinorLocator())  # Minor ticks between majors
    
    # Add grid with custom styling
    ax.grid(True, which='major', 
            alpha=AXES_STYLE['grid_alpha'], 
            zorder=0, 
            linewidth=AXES_STYLE['grid_linewidth'])
    ax.grid(True, which='minor', 
            color=AXES_STYLE['grid_color'],
            linestyle=AXES_STYLE['grid_linestyle'], 
            linewidth=AXES_STYLE['grid_linewidth'], 
            alpha=0.3)
    
    # Add legend
    ax.legend(loc='upper left',
             frameon=True, 
             fontsize=FONT_SIZES['legend'])
    
    # Set y-axis limits if specified
    if y_start is not None:
        ax.set_ylim(y_start, None)
    
    plt.tight_layout()
    
    # Save plot
    if not os.path.exists("./plots"):
        os.makedirs("./plots")
    
    plt.savefig(os.path.join(".", "plots", plot_title), bbox_inches='tight', dpi=300)
    plt.show()

# Additional utility function to create a simplified version showing only total times
def plot_kem_total_times(input_df, error_suffix="_std", plot_title="kem_total_times.png", y_start=None):
    """
    Plots total KEM timing measurements for different algorithms.
    
    Args:
        input_df: DataFrame containing the KEM timing data
        error_suffix: Suffix for error columns (default: "_std")
        plot_title: Output filename for the plot
        y_start: Starting point for y-axis (optional)
    """
    
    # Calculate total times and errors
    input_df['TotalTime_mean'] = (input_df['KeyGen(ms)_mean'] + 
                                 input_df['Encaps(ms)_mean'] + 
                                 input_df['Decaps(ms)_mean'])
    
    input_df['TotalTime_std'] = np.sqrt(
        input_df[f'KeyGen(ms){error_suffix}']**2 +
        input_df[f'Encaps(ms){error_suffix}']**2 +
        input_df[f'Decaps(ms){error_suffix}']**2
    )
    
    # Sort by total time
    input_df = input_df.sort_values('TotalTime_mean')
    
    # Create plot
    fig, ax = plt.subplots(figsize=(20, 10))
    
    # Setup plot dimensions
    
    algorithms = input_df.index.tolist()  # algorithms are in the index
    x = np.arange(len(algorithms))  # label locations
    
    x = np.arange(len(input_df.index))
    container = ax.bar(x, input_df['TotalTime_mean'],
                      yerr=input_df['TotalTime_std'],
                      capsize=3,
                      color="#33acdc",
                      edgecolor='black',
                      linewidth=1,
                      error_kw={'ecolor': 'black'},
                      zorder=3)
    
    # Apply consistent styling
    apply_axes_style(ax, 
                    xlabel='Algorithm',
                    ylabel='Time (ms)')
    
    # Set x-ticks with LaTeX formatting for underscores
    ax.set_xticks(x)
    ax.set_xticklabels([alg.replace('_', '\_') for alg in algorithms], 
                       rotation=45, 
                       horizontalalignment='right',
                       fontsize=FONT_SIZES['tick_label'])
    
    # Set major and minor tick locators
    # ax.yaxis.set_major_locator(MultipleLocator())  # Major ticks every 2 units
    ax.yaxis.set_minor_locator(AutoMinorLocator())  # Minor ticks between majors
    
    # Add grid with custom styling
    ax.grid(True, which='major', 
            alpha=AXES_STYLE['grid_alpha'], 
            zorder=0, 
            linewidth=AXES_STYLE['grid_linewidth'])
    ax.grid(True, which='minor', 
            color=AXES_STYLE['grid_color'],
            linestyle=AXES_STYLE['grid_linestyle'], 
            linewidth=AXES_STYLE['grid_linewidth'], 
            alpha=0.3)
    
    if y_start is not None:
        ax.set_ylim(y_start, None)
    
    plt.tight_layout()
    
    if not os.path.exists("./plots"):
        os.makedirs("./plots")
    
    plt.savefig(os.path.join(".", "plots", plot_title), 
                bbox_inches='tight', 
                dpi=300)
    plt.show()

def plot_kems_fast(input_df, error_suffix="_std", plot_title="fast_kems.png", y_start=None):
    """
    Plots KEM timing measurements for fast algorithms (up to qkd_frodo976aes).
    
    Args:
        input_df: DataFrame containing the KEM timing data
        error_suffix: Suffix for error columns (default: "_std")
        plot_title: Output filename for the plot
        log_scale: Boolean to enable log scale on y-axis (default: False)
    """
    
    # Filter and sort algorithms
    cutoff_alg = 'qkd_frodo976aes'
    input_df = input_df.sort_values('TotalTime_mean')
    cutoff_idx = input_df.index.get_loc(cutoff_alg) + 1
    fast_df = input_df.iloc[:cutoff_idx]
    
    # Setup plot dimensions
    width = 0.25  # width of the bars
    algorithms = fast_df.index.tolist()
    x = np.arange(len(algorithms))
    
    # Create figure
    fig, ax = plt.subplots(figsize=(20, 10))
    
    # Define colors and operations
    colors = list(mcolors.LinearSegmentedColormap.from_list("", ["#9fcf69", "#33acdc"])(np.linspace(0, 1, 3)))
    operations = ['KeyGen(ms)', 'Encaps(ms)', 'Decaps(ms)']
    
    # Plot bars for each operation
    bars = []
    for i, (operation, color) in enumerate(zip(operations, colors)):
        mean_col = f"{operation}_mean"
        std_col = f"{operation}{error_suffix}"
        
        container = ax.bar(x + (i-1)*width, 
                         fast_df[mean_col],
                         width,
                         label=operation.replace('(ms)', ''),
                         color=color,
                         edgecolor='black',
                         linewidth=1,
                         yerr=fast_df[std_col],
                         capsize=3,
                         error_kw={'ecolor': 'black'},
                         zorder=3)
        
        # Style error bars
        for line in container.errorbar.lines[2]:
            line.set_linestyle('dashed')
            line.set_linewidth(0.75)
        
        bars.append(container)
    
    # Apply consistent styling
    apply_axes_style(ax, 
                    xlabel='Algorithm',
                    ylabel='Time (ms)')
    
    # Set x-ticks with LaTeX formatting for underscores
    ax.set_xticks(x)
    ax.set_xticklabels([alg.replace('_', '\_') for alg in algorithms], 
                       rotation=45, 
                       horizontalalignment='right',
                       fontsize=FONT_SIZES['tick_label'])
    
    # Set major and minor tick locators
    # ax.yaxis.set_major_locator(MultipleLocator())  # Major ticks every 2 units
    ax.yaxis.set_minor_locator(AutoMinorLocator())  # Minor ticks between majors
    
    # Add grid with custom styling
    ax.grid(True, which='major', 
            alpha=AXES_STYLE['grid_alpha'], 
            zorder=0, 
            linewidth=AXES_STYLE['grid_linewidth'])
    ax.grid(True, which='minor', 
            color=AXES_STYLE['grid_color'],
            linestyle=AXES_STYLE['grid_linestyle'], 
            linewidth=AXES_STYLE['grid_linewidth'], 
            alpha=0.3)
    
    # Add legend with consistent styling
    ax.legend(loc='upper left',
             frameon=True, 
             fontsize=FONT_SIZES['legend'])
    
    # Set y-axis limits if specified
    if y_start is not None:
        ax.set_ylim(bottom=y_start)
    
    plt.tight_layout()
    
    # Save plot
    if not os.path.exists("./plots"):
        os.makedirs("./plots")
    
    plt.savefig(os.path.join(".", "plots", plot_title), bbox_inches='tight', dpi=300)
    plt.show()
    
def plot_kem_family(input_df, family, error_suffix="_std", plot_title=None, log_scale=False):
    """
    Plots KEM timing measurements for a specific family of algorithms.
    
    Args:
        input_df: DataFrame containing the KEM timing data
        family: String indicating which family to plot ('kyber', 'mlkem', 'bike', 'frodo', 'hqc')
        error_suffix: Suffix for error columns (default: "_std")
        plot_title: Output filename for the plot (default: family_kems.png)
        log_scale: Boolean to enable log scale on y-axis (default: False)
    """
    # Validate family selection
    family = family.lower()
    if family not in KEM_FAMILIES:
        raise ValueError(f"Unknown family '{family}'. Available families: {list(KEM_FAMILIES.keys())}")
    
    # Filter algorithms for the selected family
    family_algs = KEM_FAMILIES[family]
    family_df = input_df.loc[family_algs].sort_values('TotalTime_mean')
    
    # Setup plot dimensions
    width = 0.25  # width of the bars
    algorithms = family_df.index.tolist()
    x = np.arange(len(algorithms))
    
    # Create figure
    fig, ax = plt.subplots(figsize=(20, 10))
    
    # Define colors and operations
    colors = list(mcolors.LinearSegmentedColormap.from_list("", ["#9fcf69", "#33acdc"])(np.linspace(0, 1, 3)))
    operations = ['KeyGen(ms)', 'Encaps(ms)', 'Decaps(ms)']
    
    # Plot bars for each operation
    for i, (operation, color) in enumerate(zip(operations, colors)):
        mean_col = f"{operation}_mean"
        std_col = f"{operation}{error_suffix}"
        
        container = ax.bar(x + (i-1)*width, 
                         family_df[mean_col],
                         width,
                         label=operation.replace('(ms)', ''),
                         color=color,
                         edgecolor='black',
                         linewidth=1,
                         yerr=family_df[std_col],
                         capsize=3,
                         error_kw={'ecolor': 'black'},
                         zorder=3)
        
        # Style error bars
        for line in container.errorbar.lines[2]:
            line.set_linestyle('dashed')
            line.set_linewidth(0.75)
    
    # Apply consistent styling
    apply_axes_style(ax, 
                    xlabel='Algorithm',
                    ylabel='Time (ms)')
    
    # Set x-ticks with LaTeX formatting for underscores
    ax.set_xticks(x)
    ax.set_xticklabels([alg.replace('_', '\_') for alg in algorithms], 
                       rotation=45, 
                       horizontalalignment='right',
                       fontsize=FONT_SIZES['tick_label'])
    
    # Set major and minor tick locators
    # ax.yaxis.set_major_locator(MultipleLocator())  # Major ticks every 2 units
    ax.yaxis.set_minor_locator(AutoMinorLocator())  # Minor ticks between majors
    
    # Add grid with custom styling
    ax.grid(True, which='major', 
            alpha=AXES_STYLE['grid_alpha'], 
            zorder=0, 
            linewidth=AXES_STYLE['grid_linewidth'])
    ax.grid(True, which='minor', 
            color=AXES_STYLE['grid_color'],
            linestyle=AXES_STYLE['grid_linestyle'], 
            linewidth=AXES_STYLE['grid_linewidth'], 
            alpha=0.3)
    
    # Ensure some padding above the highest bar
    ax.margins(y=0.1)
    
    # Add legend below the title
    handles, labels = ax.get_legend_handles_labels()
    if labels:
        # Place legend below the plot title in a single row
        ax.legend(frameon=False, 
                 fontsize=FONT_SIZES['legend'],
                 loc='upper center',
                 bbox_to_anchor=(0.5, 1.01),
                 ncol=len(labels))
    
    # Set title
    ax.set_title(f'{family.upper()} Family', fontsize=FONT_SIZES['fig_title'], pad=20)
    
    plt.tight_layout()
    
    # Save plot
    if not os.path.exists("./plots"):
        os.makedirs("./plots")
    
    if plot_title is None:
        plot_title = f"{family}_kems.pdf"
    
    plt.savefig(os.path.join(".", "plots", plot_title), 
                bbox_inches='tight', 
                dpi=300)
    plt.show()
    
def plot_ops_percent(input_df, family=None, plot_title="operation_percentages.png"):
    """
    Creates a stacked bar plot showing the percentage contribution of each operation.
    
    Args:
        input_df: DataFrame containing the KEM timing data
        family: Optional string to filter for specific algorithm family
        plot_title: Output filename for the plot
    """
    
    # Filter and sort data
    if family is not None:
        if family.lower() not in KEM_FAMILIES:
            raise ValueError(f"Unknown family '{family}'. Available families: {list(KEM_FAMILIES.keys())}")
        family_algs = KEM_FAMILIES[family.lower()]
        df_to_plot = input_df.loc[family_algs]
        df_to_plot = df_to_plot.sort_values('TotalTime_mean')
    else:
        # Group by families when plotting all algorithms
        df_to_plot = pd.DataFrame()
        for fam in KEM_FAMILIES:
            family_data = input_df.loc[KEM_FAMILIES[fam]].sort_values('TotalTime_mean')
            df_to_plot = pd.concat([df_to_plot, family_data])

    # Calculate percentages
    percentages = compute_ops_percent(df_to_plot)
    
    # Setup plot dimensions
    fig, ax = plt.subplots(figsize=(20, 10))
    
    # Setup plot dimensions
    algorithms = input_df.index.tolist()  # algorithms are in the index
    x = np.arange(len(algorithms))  # label locations
    
    # Get x-axis positions
    x = np.arange(len(percentages.index))
    
    # Colors for the three operations with slight transparency
    colors = list(mcolors.LinearSegmentedColormap.from_list("", ["#9fcf69", "#33acdc"])(np.linspace(0, 1, 3)))
    colors = [mcolors.to_rgba(c, alpha=0.85) for c in colors]  # Add slight transparency
    
    # Create stacked bars
    bottom = np.zeros(len(percentages.index))
    bars = []
    labels = ['KeyGen', 'Encaps', 'Decaps']
    
    for (col, color, label) in zip(['KeyGen(ms)_mean', 'Encaps(ms)_mean', 'Decaps(ms)_mean'], 
                                 colors, labels):
        bars.append(ax.bar(x, percentages[col], bottom=bottom, label=label,
                         color=color, edgecolor='black', linewidth=1))
        bottom += percentages[col]
    
    # Add percentage labels on the bars
    for bars_group in bars:
        for bar in bars_group:
            height = bar.get_height()
            if height > 5:  # Only show label if percentage > 5%
                ax.text(bar.get_x() + bar.get_width()/2., 
                       bar.get_y() + height/2.,
                       f'{height:.1f}\%',
                       ha='center', va='center', rotation=0,
                       fontsize=14)
    
    # Apply consistent styling
    apply_axes_style(ax, 
                    xlabel=r'Algorithm',
                    ylabel=r'Percentage of Total Time (\%)')
    
    # Set x-ticks with LaTeX formatting for underscores
    ax.set_xticks(x)
    ax.set_xticklabels([alg.replace('_', '\_') for alg in algorithms], 
                       rotation=45, 
                       horizontalalignment='right',
                       fontsize=FONT_SIZES['tick_label'])
    
    ax.set_ylim(0, 100)
    ax.set_xlim(-0.5, len(algorithms) - 0.5)
    
    # Set major and minor tick locators
    ax.yaxis.set_major_locator(MultipleLocator(10))  # Major ticks every 2 units
    ax.yaxis.set_minor_locator(AutoMinorLocator())  # Minor ticks between majors
    
    # Add grid with custom styling
    ax.grid(True, which='major', 
            alpha=AXES_STYLE['grid_alpha'], 
            zorder=0, 
            linewidth=AXES_STYLE['grid_linewidth'])
    ax.grid(True, which='minor', 
            color=AXES_STYLE['grid_color'],
            linestyle=AXES_STYLE['grid_linestyle'], 
            linewidth=AXES_STYLE['grid_linewidth'], 
            alpha=0.3)
    
    # Add legend below the title
    handles, labels = ax.get_legend_handles_labels()
    if labels:
        ax.legend(frameon=False, 
                fontsize=FONT_SIZES['legend'],
                loc='upper center',
                bbox_to_anchor=(0.5, 1.1),
                ncol=len(labels))
    
    # Add title if showing a specific family
    if family is not None:
        ax.set_title(f'{family.upper()} Family', fontsize=FONT_SIZES['fig_title'], pad=20)
    
    # Add family separators when plotting all algorithms
    if family is None:
        prev_family = None
        for i, alg in enumerate(percentages.index):
            current_family = next(fam for fam, algs in KEM_FAMILIES.items() if alg in algs)
            if prev_family != current_family and i > 0:
                ax.axvline(x=i-0.5, color='black', linestyle='--', alpha=0.3, linewidth=1)
            prev_family = current_family
    
    plt.tight_layout()
    
    # Save plot
    if not os.path.exists("./plots"):
        os.makedirs("./plots")
    
    plt.savefig(os.path.join(".", "plots", plot_title), 
                bbox_inches='tight', 
                dpi=300)
    plt.show()

    # Print numerical percentages
    print("\nOperation Percentages:")
    print(percentages.round(2))
    
def plot_kem_comparison(comparison_stats, family=None, operation='TotalTime', 
                       overhead=False, plot_title=None):
    """
    Creates a comparative plot of standard vs QKD versions of KEMs.
    
    Args:
        comparison_stats: DataFrame with summary statistics
        family: KEM family to analyze ('kyber', 'mlkem', etc.) or None for all
        operation: Which timing to compare ('TotalTime', 'all')
        overhead: If True, plots overhead percentage instead of times
        plot_title: Optional filename for saving the plot
    """
    
    # Get data based on family selection
    if family is not None and family not in KEM_COMPARISON:
        raise ValueError(f"Unknown family '{family}'. Available families: {list(KEM_FAMILIES.keys())}")
    
    families_to_plot = [family] if family else KEM_COMPARISON.keys()
    operations = ['KeyGen(ms)', 'Encaps(ms)', 'Decaps(ms)']
    
    # Create figure
    fig, ax = plt.subplots(figsize=(20, 10))
    
    # Set colors
    colors = list(mcolors.LinearSegmentedColormap.from_list("", 
        ["#9fcf69", "#33acdc", "#ff7f50"])(np.linspace(0, 1, 3)))
    colors = [mcolors.to_rgba(c, alpha=0.85) for c in colors]
    
    # Configure axes style
    ax.grid(AXES_STYLE['grid'], alpha=AXES_STYLE['grid_alpha'],
            linestyle=AXES_STYLE['grid_linestyle'],
            linewidth=AXES_STYLE['grid_linewidth'],
            color=AXES_STYLE['grid_color'])
    
    ax.tick_params(which='major', length=AXES_STYLE['major_tick_length'],
                  width=AXES_STYLE['major_tick_width'])
    ax.tick_params(which='minor', length=AXES_STYLE['minor_tick_length'],
                  width=AXES_STYLE['minor_tick_width'])
    
    if operation == 'all':
        # Plot all operations
        x_positions = []
        x_labels = []
        current_x = 0
        width = 0.15
        
        # Define color palettes - one for standard, one for QKD
        std_color = "#9fcf69"  # Green for standard
        qkd_color = "#33acdc"  # Blue for QKD
        
        for fam in families_to_plot:
            std_algs = KEM_COMPARISON[fam]['standard']
            qkd_algs = KEM_COMPARISON[fam]['qkd']
            
            for std_alg, qkd_alg in zip(std_algs, qkd_algs):
                for i, op in enumerate(operations):
                    std_val = comparison_stats.loc[std_alg, f"{op}_mean"]
                    qkd_val = comparison_stats.loc[qkd_alg, f"{op}_mean"]
                    
                    # Add space between operation groups
                    x_offset = i * (3 * width)
                    
                    # Plot bars
                    ax.bar(current_x + x_offset, std_val, width,
                          label='Standard' if (current_x == 0 and i == 0) else "",
                          color=std_color, edgecolor='black', linewidth=1)
                    ax.bar(current_x + x_offset + width, qkd_val, width,
                          label='QKD' if (current_x == 0 and i == 0) else "",
                          color=qkd_color, edgecolor='black', linewidth=1)
                    
                    # Add operation label above the bars
                    if current_x == 0:  # Only add labels for first algorithm
                        op_label = op.split('(')[0]
                        ax.text(current_x + x_offset + width/2, ax.get_ylim()[1],
                               op_label, ha='center', va='bottom', 
                               fontsize=FONT_SIZES['annotation'])
                
                x_positions.append(current_x + 3*width)
                x_labels.append(std_alg.replace('_', '\_'))
                current_x += 10*width  # Increased spacing between algorithms
                
            # Add separator between families if plotting all
            if not family and fam != list(families_to_plot)[-1]:
                ax.axvline(x=current_x - 3*width, color='black', 
                          linestyle='--', alpha=0.3, linewidth=1)
                current_x += 2*width
        
        # Set x-ticks
        ax.set_xticks(x_positions)
        ax.set_xticklabels(x_labels, rotation=45, ha='right', 
                          fontsize=FONT_SIZES['tick_label'])
        
    else:
        # Plot single operation
        std_data = []
        qkd_data = []
        labels = []
        
        for fam in families_to_plot:
            std_algs = KEM_COMPARISON[fam]['standard']
            qkd_algs = KEM_COMPARISON[fam]['qkd']
            
            op_col = f"{operation}_mean"
            std_data.extend([comparison_stats.loc[alg, op_col] for alg in std_algs])
            qkd_data.extend([comparison_stats.loc[alg, op_col] for alg in qkd_algs])
            labels.extend(std_algs)
        
        x = np.arange(len(labels))
        width = 0.35
        
        if overhead:
            overhead_data = [((q - s) / s) * 100 for s, q in zip(std_data, qkd_data)]
            ax.bar(x, overhead_data, width, color=colors[0], 
                   edgecolor='black', linewidth=1)
            
            # Add percentage labels
            for i, v in enumerate(overhead_data):
                ax.text(i, v, f'{v:.1f}\%', ha='center', va='bottom', 
                       fontsize=FONT_SIZES['annotation'])
        else:
            ax.bar(x - width/2, std_data, width, label='Standard',
                   color=colors[0], edgecolor='black', linewidth=1)
            ax.bar(x + width/2, qkd_data, width, label='QKD',
                   color=colors[1], edgecolor='black', linewidth=1)
            
        ax.set_xticks(x)
        ax.set_xticklabels([label.replace('_', '\_') for label in labels],
                          rotation=45, ha='right', fontsize=FONT_SIZES['tick_label'])
    
    # Set labels and grid
    if overhead:
        ax.set_ylabel(r'\textbf{Overhead (\%)}', fontsize=FONT_SIZES['axes_label'],
                     labelpad=AXES_STYLE['label_pad'])
    else:
        ax.set_ylabel(r'\textbf{Time (ms)}', fontsize=FONT_SIZES['axes_label'],
                     labelpad=AXES_STYLE['label_pad'])
    ax.set_xlabel(r'\textbf{Algorithm}', fontsize=FONT_SIZES['axes_label'],
                 labelpad=AXES_STYLE['label_pad'])
    
    ax.yaxis.set_minor_locator(AutoMinorLocator())  # Minor ticks between majors
    
    # Add legend
    handles, labels = ax.get_legend_handles_labels()
    if labels:
        ax.legend(frameon=False, fontsize=FONT_SIZES['legend'])
    
    # Add title if showing a specific family
    if family:
        ax.set_title(f'{family.upper()} Family', fontsize=FONT_SIZES['axes_title'], 
                    pad=20)
    
    plt.tight_layout()
    
    # Save plot if title provided
    if plot_title:
        if not os.path.exists("./plots"):
            os.makedirs("./plots")
        plt.savefig(os.path.join(".", "plots", plot_title), bbox_inches='tight', dpi=300)
    
    plt.show()