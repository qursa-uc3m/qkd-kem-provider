import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
from matplotlib.ticker import AutoMinorLocator, MultipleLocator
import os

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

# Example usage:
if __name__ == "__main__":
    # Load and filter data
    df = kem_data_process("your_data.csv")
    
    # Generate summary statistics
    summary = kem_data_summary(df)
    
    print("\nFiltered Data Shape:", df.shape)
    print("\nSummary Statistics:")
    print(summary)

def plot_kem_times(input_df, error_suffix="_std", plot_title="kem_times.png", y_start=None):
    """
    Plots KEM timing measurements (KeyGen, Encaps, Decaps) for different algorithms.
    
    Args:
        input_df: DataFrame containing the KEM timing data
        error_suffix: Suffix for error columns (default: "_std")
        plot_title: Output filename for the plot
        y_start: Starting point for y-axis (optional)
    """
    fontsize_1 = 20
    fontsize_2 = 24
    
    # Sort algorithms by total time
    #input_df['TotalTime_mean'] = input_df['KeyGen(ms)_mean'] + input_df['Encaps(ms)_mean'] + input_df['Decaps(ms)_mean']
    input_df = input_df.sort_values('TotalTime(ms)_mean')
    
    # Setup plot dimensions
    width = 0.25  # width of the bars
    algorithms = input_df.index.tolist()  # algorithms are in the index
    x = np.arange(len(algorithms))  # label locations
    
    # Create color palette for the three operations
    # colors = ["#9fcf69", "#33acdc", "#ff7f50"]  # green, blue, coral
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
    
    # Customize plot
    ax.set_ylabel('Time (ms)', weight='bold', fontsize=fontsize_2)
    ax.yaxis.set_label_coords(-0.075, 0.5)
    ax.set_xlabel('Algorithm', weight='bold', fontsize=fontsize_2)
    
    # Set x-ticks
    #ax.set_xticks(x)
    #ax.set_xticklabels(algorithms, rotation=45, horizontalalignment='right')
    #ax.tick_params(axis='both', labelsize=fontsize_1)
    
    # Set x-ticks
    ax.set_xticks(x)
    ax.set_xticklabels([alg.replace('_', '\_') for alg in algorithms], 
                       rotation=45, horizontalalignment='right')
    
    # Customize tick parameters
    ax.tick_params(axis='both', which='major', length=8, width=2, labelsize=fontsize_1)
    ax.tick_params(axis='y', which='minor', length=4, width=1)
    
    #ax.yaxis.set_minor_locator(AutoMinorLocator())
    #ax.xaxis.set_minor_locator(AutoMinorLocator())
    # Set major and minor tick locators
    ax.yaxis.set_major_locator(MultipleLocator(2))  # Major ticks every 2 units
    ax.yaxis.set_minor_locator(AutoMinorLocator()) # Minor ticks between majors
    
    # Add grid
    ax.grid(True, zorder=0, alpha=0.5)
    ax.grid(which='minor', color='black', linestyle=':', linewidth=0.5, alpha=0.3)
    
    # Add legend
    ax.legend(loc='upper left', #bbox_to_anchor=(0.5, 1.15), 
             #nrow=3, 
             frameon=False, fontsize=fontsize_1)
    
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
    
    x = np.arange(len(input_df.index))
    container = ax.bar(x, input_df['TotalTime_mean'],
                      yerr=input_df['TotalTime_std'],
                      capsize=3,
                      color="#33acdc",
                      edgecolor='black',
                      linewidth=1,
                      error_kw={'ecolor': 'black'},
                      zorder=3)
    
    # Style the plot
    ax.set_ylabel('Total Time (ms)', weight='bold', fontsize=24)
    ax.set_xlabel('Algorithm', weight='bold', fontsize=24)
    ax.set_xticks(x)
    ax.set_xticklabels(input_df.index, rotation=45, ha='right')
    ax.tick_params(axis='both', labelsize=20)
    
    # Add grid
    ax.yaxis.set_minor_locator(AutoMinorLocator())
    ax.xaxis.set_minor_locator(AutoMinorLocator())
    ax.grid(True, zorder=0, alpha=0.5)
    ax.grid(which='minor', color='black', linestyle=':', linewidth=0.5, alpha=0.3)
    
    if y_start is not None:
        ax.set_ylim(y_start, None)
    
    plt.tight_layout()
    
    if not os.path.exists("./plots"):
        os.makedirs("./plots")
    
    plt.savefig(os.path.join(".", "plots", plot_title), bbox_inches='tight', dpi=300)
    plt.show()
