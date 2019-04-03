import re,  hashlib

def main():

    IN_FILENAME = "access.log"
    OUT_FILENAME = "processed_log.csv"
    SALT_VALUE = ".118.999"

    dictlist_nginx = extract_to_dict(
        in_filename = IN_FILENAME)
    print dictlist_nginx
    return 7
    convert_to_csv(
        input_list = dictlist_nginx,
        salt_value = SALT_VALUE,
        out_filename = OUT_FILENAME)

def extract_to_dict(in_filename = None):

    # Ensure parameter is supplied.
    if in_filename:

        # Specify Regular Expression to process nginx logs.
        access_regex = re.compile(r'(?P<remoteAddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) ' +\
            '- - \[(?P<timeLocal>\d{2}\/[a-zA-Z]{3}\/\d{4}\:\d{2}\:\d{2}\:\d{2}\s\+\d{4})\] ' +\
            '"(?P<request>.+?(?="))" (?P<status>\d{3}) (?P<bodyBytesSent>\d+) "(?P<httpReferer' +\
            '>.+?(?="))" "(?P<httpUserAgent>.+?(?="))"')

        # Read in the data from the input file.
        input_ptr = open(in_filename, 'r')

        # Define a list to append the dictionaries to.
        generated_list = []

        # Process each line and append using the regex.
        for line in input_ptr.readlines():
            #print line
            processed_data = access_regex.match(line)
            #print processed_data
            generated_list.append(processed_data.groupdict())

        # Return the generated dictionaries as a list.
        return generated_list

def convert_to_csv(input_list = None, salt_value = None, out_filename = None, 
    fields = ["remoteAddress", "timeLocal", "request", "status"]):
    
    # Ensure parameters are supplied.
    if input_list and salt_value and out_filename:
    
        # Convert supplied list to a dataframe.
        df_data = pandas.DataFrame(input_list)

        # Obfuscate the IP addresses of each user, using a salted hash.
        df_data["remoteAddress"] = df_data["remoteAddress"]\
            .map(lambda v: hashlib.sha512(v + salt_value).hexdigest())

        # Remove unnecessary fields.
        df_data = df_data[fields]

        # Dump the DataFrame to file.
        df_data.to_csv(filename = out_filename)

main()
