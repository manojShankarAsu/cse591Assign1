from application import application

def add_to_index(index, obj_id,content):
    if not application.elasticsearch:
        return
    application.elasticsearch.index(index=index, doc_type=index, id=obj_id,
                                    body=content)

def remove_from_index(index, obj_id):
    if not application.elasticsearch:
        return
    application.elasticsearch.delete(index=index, doc_type=index, id=obj_id)

def query_index(index, query, page, per_page):
    if not application.elasticsearch:
        return [], 0
    search = application.elasticsearch.search(
        index=index, doc_type=index,
        body={'query': {'multi_match': {'query': query, 'fields': ['*']}},
              'from': (page - 1) * per_page, 'size': per_page})
    ids = [int(hit['_id']) for hit in search['hits']['hits']]
    return ids, search['hits']['total']