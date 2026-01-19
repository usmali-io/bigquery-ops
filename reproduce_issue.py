
import gradio as gr
import time

def slow_echo(x):
    time.sleep(1)
    return x

with gr.Blocks() as demo:
    txt = gr.Textbox(label="Input")
    
    # Standard setup with components
    ds = gr.Dataset(components=[txt], samples=[["Hello"], ["World"]])
    
    # 1. Default (Implicit?) - Does clicking update txt?
    # By default, Dataset updates components WITHOUT explicit click handler if components are passed? 
    # Actually docs say "When a user clicks on an example, the values of the components will be updated."
    
    # 2. explicit click with None
    ds.click(fn=None, inputs=[ds], outputs=[txt])
    
    # 3. Another dataset with Python handler (Slow)
    ds_slow = gr.Dataset(components=[txt], samples=[["Slow"], ["Down"]], label="Slow Dataset")
    ds_slow.click(slow_echo, inputs=[ds_slow], outputs=[txt])

if __name__ == "__main__":
    demo.launch(server_port=7861)
