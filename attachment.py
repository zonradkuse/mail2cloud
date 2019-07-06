class Attachment(object):

    def __init__(self, name, data, length, content_type, origin):
        self.name = name
        self.data = data
        self.length = length
        self.content_type = content_type
        self.origin = origin

    def __str__(self):
        return f"[{self.length} byte; {self.content_type}; {self.name}]"

