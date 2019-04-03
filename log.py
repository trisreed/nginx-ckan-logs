#!/usr/bin/env python3
"""
NGiИX Log File Analysis for CKAN: This script is used to determine common 
search queries on a CKAN instance behind an NGiИX web server.
"""


__author__ = "Tristan W. Reed"
__version__ = "0.9.0"


""" Import required libraries. """
import hashlib, pandas, re, sys, random


def main():

    """ Check that two arguments have been supplied. """
    if (len(sys.argv) != 3):

        """ Check if they supplied one argument called '--help'. """
        if ((len(sys.argv) == 2) and (sys.argv[1] == "--help")):
        
            """ Tell the user how to use the program. """
            print("""
            NGiИX Log File Analysis for CKAN
            ----------------------------------------
            Usage: log.py <INPUT_FILE> <OUTPUT_FILE>
            <INPUT_FILE>: Path to an NGiИX log in `access.log` default format;
            <OUTPUT_FILE>: Path to write the output of the analysis.
            ----------------------------------------
            Program maintained by Tristan Reed, GitHub username 'trisreed'.
            """)
        
        else:

            """ Tell the user they're doing it wrong. """
            print("""
            NGiИX Log File Analysis for CKAN
            ----------------------------------------
            Invalid invocation! Try 'log.py --help' for instructions.
            """)
        
    else:

        """ Let's actually do this. Extract the arguments for simplicity's 
        sake from 'sysv'. """
        input_filename = sys.argv[1]
        output_filename = sys.argv[2]

        """ Generate a random salt (really doesn't need to be in this format, 
        but it's fun). """
        salt_value = str(random.randint(0, 255)) + "." + str(random.randint(0, 
            255))
        
        """ Call out dictionary creation function. """
        nginx_dict = extract_to_dict(in_filename = input_filename)

        """ Process the Dictionary. """
        nginx_dict = process_dict(in_dictionary = nginx_dict)
        
        """ Dump this to a CSV. """
        convert_to_csv(input_list = nginx_dict, salt_value = salt_value, 
            out_filename = output_filename)


def extract_to_dict(in_filename = None):

    """ Specify Regular Expression to process nginx logs. """
    access_regex = re.compile(r'(?P<remoteAddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) ' +\
        '- - \[(?P<timeLocal>\d{2}\/[a-zA-Z]{3}\/\d{4}\:\d{2}\:\d{2}\:\d{2}\s\+\d{4})\] ' +\
        '"(?P<request>.+?(?="))" (?P<status>\d{3}) (?P<bodyBytesSent>\d+) "(?P<httpReferer' +\
        '>.+?(?="))" "(?P<httpUserAgent>.+?(?="))"')

    """ Read in the data from the input file. """
    input_ptr = open(in_filename, 'r')

    """ Define a list to append the dictionaries to. """
    generated_list = []

    """ Process each line and append using the regex. """
    for line in input_ptr.readlines():

        """ Do the regexing. """
        processed_data = access_regex.match(line)

        """ Place it into the list. """
        generated_list.append(processed_data.groupdict())

    """ Return the generated dictionaries as a list. """
    return(generated_list)


def process_dict(in_dictionary = None):

    """ Create a new Dictionary List for output. """
    new_list = []

    """ Iterate over the Dictionary List. """
    for each_dictionary in in_dictionary:

        """ Create a new Dictionary for the List. """
        new_dictionary = {}

        """ Check if a request was made (should be!) """
        if ("request" in each_dictionary):

            """ Determine if the 'dataset' endpoint has been hit (i.e. where 
            searches do occur). """
            if (each_dictionary["request"].startswith("GET /dataset")):

                """ Strip that from the front. """
                stripped_request = each_dictionary["request"]\
                    .lstrip("GET /dataset?").rstrip(" HTTP/1.1")

                """ Pull out the query parameters. """
                query_params = stripped_request.split("&")

                """ Split those on the equals sign to get key/values. """
                query_params = [query.split("=") for query in query_params]

                """ Loop through these parameters. """
                for parameter_set in query_params:
                
                    """ If the first (key) value is either 'q' or 'page', we 
                    are interested. If not, ignore it. """
                    if ((parameter_set[0] == "q") and \
                        (len(parameter_set) > 1)):

                        """ Pull out the 'q' value and add it to our 'return 
                        dictionary'. """
                        new_dictionary["query"] = parameter_set[1].replace("+", 
                            " ")

                    """ Now, consider page. """
                    if ((parameter_set[0] == "page") and \
                        (len(parameter_set) > 1)):

                        """ If empty, consider it one. """
                        if (parameter_set[1] == ""):

                            """ Put the value in. """
                            new_dictionary["page"] = 1

                        else:

                            """ Pull out the value and add it to our 'return 
                            dictionary'. """
                            new_dictionary["page"] = int(parameter_set[1])
                    
                    else:

                        """ Otherwise, the page is 1. """
                        new_dictionary["page"] = 1      
  
        """ If we have the IP address, add it. """
        if ("remoteAddress" in each_dictionary):

            """ Do the magic. """
            new_dictionary["ip"] = each_dictionary["remoteAddress"]

        """ Same with the local time. """
        if ("timeLocal" in each_dictionary):

            """ Do the magic. """
            new_dictionary["time"] = each_dictionary["timeLocal"]
        
        """ Put that dictionary into the big one, if a query was specified. """
        if (("query" in new_dictionary) and (new_dictionary["query"] != "")):
        
            """ Go and do it. """
            new_list.append(new_dictionary)
    
    """ Return that to the caller. """
    return(new_list)
                

def convert_to_csv(input_list = None, salt_value = None, out_filename = None):
    
    """ Convert supplied list to a dataframe. """
    df_data = pandas.DataFrame(input_list)

    """ Obfuscate the IP addresses of each user, using a salted hash. """
    df_data["ip"] = df_data["ip"].map(lambda v: hashlib.sha512(bytes(
        v + salt_value, 'ascii')).hexdigest())

    """ Group by the Query and the User. """
    df_data = df_data.groupby(["ip", "query"])["page"].max().reset_index()

    """ Group by the Query and get the average number of pages and total number 
    of searches. """
    df_data = df_data.groupby(["query"]).apply(_do_aggregation)\
        .reset_index()

    """ Round the mean to 1dp. """
    df_data["mean"] = df_data["mean"].round(1)

    """ Sort by the Count then the Mean. """
    df_data = df_data.sort_values(["count", "mean"], ascending = False)

    """ Dump the DataFrame to file. """
    df_data.to_csv(out_filename, index = None)


def _do_aggregation(x):

    """ Define the columns and operations. """
    names = {'count': x['page'].count(), 'mean':  x['page'].mean()}

    """ Return to the Caller. """
    return pandas.Series(names, index = ['count', 'mean'])


if __name__ == "__main__":

    """ This is executed when run from the command line. """
    main()
