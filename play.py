import click
from os import path
from playsound import playsound
from time import sleep


@click.command()
@click.option('-a', '--audio', 'filename')
@click.option('-s', '--speed', 'speed')
def play(filename, speed):
    if path.isfile(f'./sound/{filename}.wav'):
        playsound(f'./sound/{filename}.wav')
        sleep(1)


play()

