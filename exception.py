class MyException(Exception):
    def __init__(self, message='', status_code=None):
        self.message = message
        if status_code is not None:
            self.status_code = status_code

    def error_to_dict(self):
        error = dict()
        error['message'] = self.message
        error['status_code'] = self.status_code

        return error


