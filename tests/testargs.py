def add(args):
    print('add', args.__dict__)
    print('add', args.filename)
    if args.set:
        print('add', args.data)
def remove(args):
    print('remove', args.__dict__)
def find(args):
    print('find', args.__dict__)
def list_info(args):
    print('list', args.__dict__)
def convert(args):
    print('convert', args.__dict__)
def change_password(args):
    print('change_password', args.__dict__)
if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser(description="Password manager")
    subparsers = parser.add_subparsers(help="sub-command help")
    convert_group = subparsers.add_parser('convert', help='Add an item')
    convert_group.add_argument('filename')
    convert_group.set_defaults(func=convert)

    change_password_group = subparsers.add_parser('change_password', help='Add an item')
    change_password_sub = change_password_group.add_subparsers(help="sub-command help")
    change_password_sub_group = change_password_sub.add_parser('for', help="filename")
    change_password_sub_group.add_argument('filename')
    change_password_group.set_defaults(func=change_password)

    list_group = subparsers.add_parser('list', help='Add an item')
    list_group.add_argument('account', action='store',
                            help='The item to operate on')
    list_sub = list_group.add_subparsers(help="sub-command help")
    list_sub_group = list_sub.add_parser('in', help="filename")
    list_sub_group.add_argument('filename')
    list_group.set_defaults(func=list_info)

    find_group = subparsers.add_parser('find', help='Add an item')
    find_group.add_argument('search_term', action='store',
                            help='The item to operate on')
    find_sub = find_group.add_subparsers(help="sub-command help")
    find_sub_group = find_sub.add_parser('in', help="filename")
    find_sub_group.add_argument('filename')
    find_group.set_defaults(func=find)

    add_group = subparsers.add_parser('add', help='Add an item')
    add_group.add_argument('account', action='store',
                            help='The item to operate on')
    add_group.add_argument('-s', '--seperator',  action='store', default='=',
                            help='Set the info seperator (default is "=")')
    add_sub = add_group.add_subparsers(help="sub-command help", dest='to')
    add_sub.required = True
    add_sub_group = add_sub.add_parser('to', help="filename")
    add_sub_group.add_argument('filename')
    file_sub = add_sub_group.add_subparsers(help="sub-command help", dest='set')
    file_sub_group = file_sub.add_parser('set', help='Set item info.')
    file_sub_group.add_argument('data', nargs="+", help='Use {secret} to input \
                            secrets e.g. (Question={secret})')
    add_group.set_defaults(func=add)

    remove_group = subparsers.add_parser('remove', help='Remove an item')
    remove_group.add_argument('account', action='store',
                            help='The item to operate on')
    remove_sub = remove_group.add_subparsers(help="sub-command help")
    remove_sub_group = remove_sub.add_parser('from', help="filename")
    remove_sub_group.add_argument('filename')
    remove_group.set_defaults(func=remove)

    args, leftovers = parser.parse_known_args()
    args.func(args)
