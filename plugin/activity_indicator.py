import uuid
from threading import Lock

import sublime


class ActivityIndicator:
    STYLES = {
        'bar': {
            'func': lambda width, tick: '{}[{}{}{}]'.format(
                '{label}',
                ' ' * min(tick % (2 * width), (2 * width) - (tick % (2 * width))),
                '=',
                ' ' * (width - min(tick % (2 * width), (2 * width) - (tick % (2 * width))))
            ),
            'width': 10,
            'interval': 100
        },
        'bouncing_ball': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                ' ' * (abs((tick % (width * 2)) - width)) + '●' + ' ' * (width - abs((tick % (width * 2)) - width))
            ),
            'width': 10,
            'interval': 150
        },
        'shark': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                '~' * (abs((tick % (width * 2)) - width)) + '^' + '~' * (width - abs((tick % (width * 2)) - width))
            ),
            'width': 10,
            'interval': 200
        },
        'spinning': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                ['|', '/', '-', '\\'][(tick % 4)]
            ),
            'width': 1,
            'interval': 150
        },
        'circle': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                ['◯', '◉'][(tick % 2)]
            ),
            'width': 1,
            'interval': 300
        },
        'arrows': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                ['→', '↘', '↓', '↙', '←', '↖', '↑', '↗'][(tick % 8)]
            ),
            'width': 1,
            'interval': 150
        },
        'elastic_dots': {
            'func': lambda width, tick: '{}[{}{}{}]'.format(
                '{label}',
                '.' * (tick % width),
                ' ' * ((width - (tick % width)) // 2),
                '.' * ((width - (tick % width)) // 2)
            ),
            'width': 10,
            'interval': 100
        },
        'steps': {
            'func': lambda width, tick: '{}[{}{}]'.format(
                '{label}',
                '▮' * (tick % (width + 1)),
                ' ' * (width - (tick % (width + 1)))
            ),
            'width': 5,
            'interval': 150
        },
        'caterpillar': {
            'func': lambda width, tick: '{}[{}{}{}]'.format(
                '{label}',
                ' ' * (tick % width),
                '◉' * ((width - (tick % width)) % width),
                ' ' * (tick % width)
            ),
            'width': 10,
            'interval': 150
        },
        'rotating_box': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                ['◰', '◳', '◲', '◱'][(tick % 4)]
            ),
            'width': 1,
            'interval': 150
        },
        'wave': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                ''.join(['~' if (i + tick) % 4 == 0 else ' ' for i in range(width)])
            ),
            'width': 10,
            'interval': 200
        },
        'wave_animation': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                ''.join(['°º¤ø,¸¸,ø¤º°'[(i + tick) % len('°º¤ø,¸¸,ø¤º°')] for i in range(width)])
            ),
            'width': 10,
            'interval': 250
        },
        'dots': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                ' '.join(['•' if i == tick % width else ' ' for i in range(width)])
            ),
            'width': 10,
            'interval': 100
        },
        'dots_wave': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                ''.join(['.' if (i + tick) % 4 == 0 else ' ' for i in range(width)])
            ),
            'width': 10,
            'interval': 200
        },
        'scrolling_dots': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                ' ' * (tick % width) + '.' + ' ' * (width - (tick % width) - 1)
            ),
            'width': 10,
            'interval': 100
        },
        'zigzag': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                ''.join(['/' if (i + tick) % 4 == 0 else '\\' if (i + tick) % 4 == 2 else ' ' for i in range(width)])
            ),
            'width': 10,
            'interval': 150
        },
        'chase': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                ' ' * (width - 1) + '●' if tick % (width * 2) < width else '●' + ' ' * (width - 1)
            ),
            'width': 10,
            'interval': 100
        },
        'shifting': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                ' ' * ((tick % width) % width) + '◉' + ' ' * (width - ((tick % width) % width) - 1)
            ),
            'width': 10,
            'interval': 150
        }
    }

    def __init__(self, view, label=None, width=None, interval=None, style='bar'):
        self.view = view
        self.label = label + ' ' if label else ''
        if style not in self.STYLES:
            raise ValueError('Invalid style. Choose from: {}'.format(', '.join(self.STYLES.keys())))

        style_defaults = self.STYLES[style]
        self.width = width if width is not None else style_defaults['width']
        self.interval = interval if interval is not None else style_defaults['interval']
        self.style = style
        self.key = 'ai-{}'.format(uuid.uuid4())
        self._running = False
        self._tick = 0
        self._lock = Lock()

    def set(self, message):
        self.view.set_status(self.key, message)

    def erase(self):
        self.view.erase_status(self.key)

    def _schedule_update(self):
        sublime.set_timeout_async(self._update_display, self.interval)

    def _update_display(self):
        with self._lock:
            if not self._running:
                return

            style_func = self.STYLES[self.style]['func']
            message = style_func(self.width, self._tick).format(label=self.label)
            self.set(message)
            self._tick += 1

        self._schedule_update()

    def start(self):
        with self._lock:
            if self._running:
                raise RuntimeError('Activity indicator is already running')
            self._running = True
            self._tick = 0
            self._schedule_update()

    def stop(self):
        with self._lock:
            self._running = False
            self.erase()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()

    def __del__(self):
        self.erase()
