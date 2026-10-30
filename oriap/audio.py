import numpy as np
from aiortc import AudioStreamTrack


class ToneTrack(AudioStreamTrack):
    """Piste audio de test : sinusoïde (440 Hz par défaut)."""

    def __init__(self, freq: float = 440.0):
        super().__init__()
        self.freq, self._t = freq, 0

    async def recv(self):
        frame = await super().recv()
        n = frame.samples
        t = (self._t + np.arange(n)) / frame.sample_rate
        self._t += n
        wave = (0.3 * 32767 * np.sin(2 * np.pi * self.freq * t)).astype(np.int16)
        frame.planes[0].update(np.repeat(wave[:, None], len(frame.layout.channels), axis=1).tobytes())
        return frame
