import random

from ..core import Module, log

DOTFILES = []
MODULE_CONFIG = {
    'source': 'build-in',
    'name': 'Sf LoremIpsum',
    'uid': 'sfloremipsum',
    'type': 'converter',
    'syntaxes': ['*'],
    'exclude_syntaxes': None,
    'executable_path': None,
    'args': ['--length', 3, '--length_in', 'paragraphs', '--begin_with_lorem', True, '--use_custom_text', False],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path". Set "--length_in" to "paragraphs", "sentences", "words". Set "--use_custom_text" to true to use the current text in your language (e.g. Chinese).'
}


class SfloremipsumFormatter(Module):
    word_list = [
        'lorem', 'ipsum', 'dolor', 'sit', 'amet', 'consectetur',
        'adipiscing', 'elit', 'sed', 'do', 'eiusmod', 'tempor',
        'incididunt', 'ut', 'labore', 'et', 'dolore', 'magna',
        'aliqua', 'ut', 'enim', 'ad', 'minim', 'veniam',
        'quis', 'nostrud', 'exercitation', 'ullamco', 'laboris',
        'nisi', 'ut', 'aliquip', 'ex', 'ea', 'commodo',
        'consequat', 'duis', 'aute', 'irure', 'dolor', 'in',
        'reprehenderit', 'in', 'voluptate', 'velit', 'esse',
        'cillum', 'dolore', 'eu', 'fugiat', 'nulla', 'pariatur',
        'excepteur', 'sint', 'occaecat', 'cupidatat', 'non',
        'proident', 'sunt', 'in', 'culpa', 'qui', 'officia',
        'deserunt', 'mollit', 'anim', 'id', 'est', 'laborum'
    ]

    AVERAGE_SENTENCE_LENGTH = 15
    SENTENCE_LENGTH_VARIATION = 9
    AVERAGE_PARAGRAPH_LENGTH = 5
    PARAGRAPH_LENGTH_VARIATION = 2
    COMMA_INSERTION_PROBABILITY = 0.6
    MINIMUM_WORDS_PER_SENTENCE = 4
    MINIMUM_WORD_COUNT = 10

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def word_list_from_text(self, text):
        words = text.lower().split()
        unique_words_list = list(set(word for word in words if word.isalpha()))
        return unique_words_list

    def generate_paragraphs(self, length, begin_with_lorem=False):
        paragraphs = []
        for _ in range(length):
            paragraph_length = self.get_random_length(self.AVERAGE_PARAGRAPH_LENGTH, self.PARAGRAPH_LENGTH_VARIATION)
            sentences = [
                self.format_sentence(self.get_words(self.get_random_length(self.AVERAGE_SENTENCE_LENGTH, self.SENTENCE_LENGTH_VARIATION)))
                for _ in range(paragraph_length)
            ]
            paragraph = self.format_paragraph(sentences)
            if begin_with_lorem and _ == 0:
                paragraph = self.replace_start(paragraph)
            paragraphs.append(paragraph)

        return '\n\n'.join(paragraphs).rstrip()

    def generate_sentences(self, length, begin_with_lorem=False):
        sentences = [
            self.format_sentence(self.get_words(self.get_random_length(self.AVERAGE_SENTENCE_LENGTH, self.SENTENCE_LENGTH_VARIATION)))
            for _ in range(length)
        ]

        if begin_with_lorem and sentences:
            sentences[0] = 'Lorem ipsum ' + sentences[0][0].lower() + sentences[0][1:]

        return ' '.join(sentences)

    def generate_words(self, length):
        words = self.get_words(length)
        return ' '.join(words).capitalize() + '.'

    def get_words(self, length):
        words = []
        prev_word = None
        while len(words) < length:
            word = random.choice(self.word_list)
            if word != prev_word:
                words.append(word)
                prev_word = word
        return words

    def format_sentence(self, words):
        if len(words) < self.MINIMUM_WORDS_PER_SENTENCE:
            return ' '.join(words).capitalize() + '.' if words else ''

        if random.random() < self.COMMA_INSERTION_PROBABILITY and len(words) > 2:
            comma_position = random.randint(1, len(words) - 2)
            words[comma_position] += ','

        sentence = ' '.join(words).capitalize() + '.'
        return sentence

    def format_paragraph(self, sentences):
        return ' '.join(sentences)

    def replace_start(self, paragraph):
        words = paragraph.split(' ')
        if len(words) > 5:
            words[:5] = ['Lorem', 'ipsum', 'dolor', 'sit', 'amet']
        else:
            lorem = ['Lorem', 'ipsum', 'dolor', 'sit', 'amet']
            words = lorem[:len(words)]
            words[-1] += '.'
        return ' '.join(words)

    def get_random_length(self, mean, std_dev):
        length = max(self.MINIMUM_WORDS_PER_SENTENCE, int(random.gauss(mean, std_dev)))
        return length

    def format(self):
        try:
            text = self.get_text_from_region(self.region)
            args = self.parse_args(convert=True)
            length = args.get('--length', 3)
            length_in = args.get('--length_in', 'paragraphs')
            begin_with_lorem = args.get('--begin_with_lorem', False)
            use_custom_text = args.get('--use_custom_text', False)

            if use_custom_text:
                unique_words = self.word_list_from_text(text)
                if len(unique_words) < self.MINIMUM_WORD_COUNT:
                    log.warning('Input text must contain at least %d unique words. Falling back to default "lorem" text.', self.MINIMUM_WORD_COUNT)
                else:
                    self.word_list = unique_words

            if length_in == 'paragraphs':
                text = self.generate_paragraphs(length, begin_with_lorem)
            elif length_in == 'sentences':
                text = self.generate_sentences(length, begin_with_lorem)
            elif length_in == 'words':
                text = self.generate_words(length)
            else:
                raise ValueError('Unsupported length_in value: %s' % length_in)

            return text
        except Exception as e:
            log.status('Formatting failed due to error: %s', e)
            return None
