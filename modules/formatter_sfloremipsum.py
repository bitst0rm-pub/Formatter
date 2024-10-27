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
    'args': ['--length', 3, '--length_in', 'paragraphs', '--begin_with_lorem', True],
    'config_path': None,
    'comment': 'Build-in, no "executable_path", no "config_path". Use "args" with "--length_in" "paragraphs", "sentences", "words".'
}


class SfloremipsumFormatter(Module):
    word_list = ['lorem', 'ipsum', 'dolor', 'sit', 'amet', 'consectetur', 'adipiscing', 'elit', 'sed', 'do', 'eiusmod', 'tempor', 'incididunt', 'ut', 'labore', 'et', 'dolore', 'magna', 'aliqua', 'ut', 'enim', 'ad', 'minim', 'veniam', 'quis', 'nostrud', 'exercitation', 'ullamco', 'laboris', 'nisi', 'ut', 'aliquip', 'ex', 'ea', 'commodo', 'consequat', 'duis', 'aute', 'irure', 'dolor', 'in', 'reprehenderit', 'in', 'voluptate', 'velit', 'esse', 'cillum', 'dolore', 'eu', 'fugiat', 'nulla', 'pariatur', 'excepteur', 'sint', 'occaecat', 'cupidatat', 'non', 'proident', 'sunt', 'in', 'culpa', 'qui', 'officia', 'deserunt', 'mollit', 'anim', 'id', 'est', 'laborum']
    AVERAGE_SENTENCE_LENGTH = 15
    SENTENCE_LENGTH_VARIATION = 9
    AVERAGE_PARAGRAPH_LENGTH = 5
    PARAGRAPH_LENGTH_VARIATION = 2
    COMMA_INSERTION_PROBABILITY = 0.6
    MINIMUM_WORDS_PER_SENTENCE = 4

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

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

    def words_to_sentences(self, words):
        sentences = []
        while words:
            sentence_length = self.get_random_length(self.AVERAGE_SENTENCE_LENGTH, self.SENTENCE_LENGTH_VARIATION)

            while sentence_length < self.MINIMUM_WORDS_PER_SENTENCE:
                sentence_length = self.get_random_length(self.AVERAGE_SENTENCE_LENGTH, self.SENTENCE_LENGTH_VARIATION)

            sentence_words = words[:sentence_length]
            del words[:sentence_length]
            sentences.append(self.format_sentence(sentence_words))
        return sentences

    def sentences_to_paragraphs(self, sentences):
        paragraphs = []
        while sentences:
            paragraph_length = self.get_random_length(self.AVERAGE_PARAGRAPH_LENGTH, self.PARAGRAPH_LENGTH_VARIATION)
            paragraph_sentences = sentences[:paragraph_length]
            del sentences[:paragraph_length]
            paragraphs.append(self.format_paragraph(paragraph_sentences))
        return paragraphs

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
            args = self.parse_args(convert=True)
            length = args.get('--length', 3)
            length_in = args.get('--length_in', 'paragraphs')
            begin_with_lorem = args.get('--begin_with_lorem', False)

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
            log.status('File not formatted due to error: %s', e)
            return None
