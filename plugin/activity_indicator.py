import uuid
from threading import Lock
from time import perf_counter

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
        'fancy_wave': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                ''.join(['°º¤ø,¸¸,ø¤º°'[(i + tick) % len('°º¤ø,¸¸,ø¤º°')] for i in range(width)])
            ),
            'width': 10,
            'interval': 200
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
        'dancing_lines': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                ''.join(['/' if (i + tick) % 2 == 0 else '\\' for i in range(width)])
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
        },
        'braille_spinner': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                '⣷⣯⣟⡿⢿⣻⣽⣾'[(tick % 8)]
            ),
            'width': 1,
            'interval': 150
        },
        'syncopated_rhythm': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                ''.join([['⣷', '⣯', '⣟', '⡿', '⢿', '⣻', '⣽', '⣾'][(tick + i) % 8] if (i % 4) == 0 else '' for i in range(width)])
            ),
            'width': 8,
            'interval': 200
        },
        'dancing_bars': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                ''.join([['⣷', '⣯', '⣟', '⡿', '⢿', '⣻', '⣽', '⣾'][(i + tick) % 8] if i % 2 == 0 else ' ' for i in range(width)])
            ),
            'width': 8,
            'interval': 150
        },
        'pulsing_wave': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                ' '.join([['⣷', '⣯', '⣟', '⡿', '⢿', '⣻', '⣽', '⣾'][(tick + i) % 8] for i in range(width)])
            ),
            'width': 8,
            'interval': 150
        },
        'square_spinner': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                '▖▘▝▗'[(tick % 4)]
            ),
            'width': 1,
            'interval': 150
        },
        'line_bounce': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                ('-' * (tick % width) + '|' + '-' * (width - (tick % width) - 1))
            ),
            'width': 10,
            'interval': 100
        },
        'circle_spinner': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                '◐◓◑◒'[(tick % 4)]
            ),
            'width': 1,
            'interval': 150
        },
        'pulse': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                '●◐◒◓◉◓◒◐'[(tick % 8)]
            ),
            'width': 1,
            'interval': 200
        },
        'heartbeat': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                '❤   ❤' if (tick % 4) < 2 else '   ❤   '
            ),
            'width': 1,
            'interval': 300
        },
        'twirl': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                '▹▸▻►▹▸▻►'[(tick % 8)]
            ),
            'width': 1,
            'interval': 150
        },
        'starry_night': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                '✶✸✹✺✹✷✶'[(tick % 7)]
            ),
            'width': 1,
            'interval': 150
        },
        'flip': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                '┤┘┴└├┌┬┐'[(tick % 8)]
            ),
            'width': 1,
            'interval': 100
        },
        'rolling_dice': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                '⚀⚁⚂⚃⚄⚅'[(tick % 6)]
            ),
            'width': 1,
            'interval': 200
        },
        'box_spinner': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                '▛▜▟▙'[(tick % 4)]
            ),
            'width': 1,
            'interval': 150
        },
        'dots_carousel': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'[(tick % 10)]
            ),
            'width': 1,
            'interval': 150
        },
        'signal_strength': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                '▁▃▅▇'[(tick % 4)]
            ),
            'width': 1,
            'interval': 150
        },
        'rolling_circle': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                '◴◷◶◵'[(tick % 4)]
            ),
            'width': 1,
            'interval': 100
        },
        'clock': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                '🕛🕐🕑🕒🕓🕔🕕🕖🕗🕘🕙🕚'[(tick % 12)]
            ),
            'width': 1,
            'interval': 150
        },
        'moon_phases': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                '🌑🌒🌓🌔🌕🌖🌗🌘'[(tick % 8)]
            ),
            'width': 1,
            'interval': 200
        },
        'traffic_lights': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                '🔴🟠🟢'[(tick % 3)]
            ),
            'width': 1,
            'interval': 300
        },
        'emoji_bounce': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                '😀😃😄😁😆😅😂🤣'[(tick % 8)]
            ),
            'width': 1,
            'interval': 200
        },
        'ping_pong': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                '🏓 ' if tick % 2 == 0 else ' 🏓'
            ),
            'width': 1,
            'interval': 200
        },
        'colorful_blocks': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                '🟦🟧🟨🟩🟦🟧🟨🟩'[(tick % 8)]
            ),
            'width': 1,
            'interval': 200
        },
        'rotating_earth': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                '🌍🌎🌏'[(tick % 3)]
            ),
            'width': 1,
            'interval': 250
        },
        'balloon_pop': {
            'func': lambda width, tick: '{}[{}]'.format(
                '{label}',
                '🎈' if tick % 2 == 0 else '💥'
            ),
            'width': 1,
            'interval': 300
        }
    }

    def __init__(self, view=None, label=None, width=None, interval=None, style='bar', delay=0):
        self.view = view
        self.label = label + ' ' if label else ''
        if style not in self.STYLES:
            raise ValueError('Invalid style. Choose from: {}'.format(', '.join(self.STYLES.keys())))
        style_defaults = self.STYLES[style]
        self.width = width if width is not None else style_defaults['width']
        self.interval = interval if interval is not None else style_defaults['interval']
        self.style = style
        self.key = '{}_i'.format(uuid.uuid4())
        self._running = False
        self._tick = 0
        self._lock = Lock()
        self._start_time = 0
        self._delay = delay / 1000  # seconds

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.stop()

    def __del__(self):
        self.erase()

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

    def delayed_start(self):
        if perf_counter() - self._start_time >= self._delay:
            with self._lock:
                if self._running:
                    self._schedule_update()

    def start(self):
        with self._lock:
            if self._running:
                raise RuntimeError('Activity indicator is already running')
            self._running = True
            self._tick = 0
            self._start_time = perf_counter()
            if self._delay > 0:
                sublime.set_timeout(self.delayed_start, int(self._delay * 1000))
            else:
                self._schedule_update()

    def stop(self):
        with self._lock:
            self._running = False
            self.erase()

    def _test_all_styles(self, duration=5):  # 5s
        # Test case to display all available styles
        def _test_styles(styles, index):
            if index >= len(styles):
                self.erase()
                return

            style = styles[index]
            self.style = style
            self.width = self.STYLES[style]['width']
            self.interval = self.STYLES[style]['interval']

            # Update the label to include the style name
            self.label = '{}: '.format(style)

            self.start()

            # Stop displaying the current style after duration in seconds
            sublime.set_timeout(lambda: self.stop(), duration * 1000)

            # Schedule the next style to start after duration in seconds plus a small delay
            sublime.set_timeout(lambda: _test_styles(styles, index + 1), (duration + 0.1) * 1000)

        all_styles = list(self.STYLES.keys())
        _test_styles(all_styles, 0)
