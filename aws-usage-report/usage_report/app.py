import json
import boto3
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

def getEC2rows(region_name):
    ec2 = boto3.resource('ec2', region_name=region_name)
    ec2Rows = ""
    for instance in ec2.instances.all():
        theOwner ='<span class="badge bg-warning text-dark">No Owner</span>'
        theUsage ='<span class="badge bg-warning text-dark">No Usage</span>'
        theName = '<span class="badge bg-warning text-dark">No Name</span>'

        # Analyszing Tags
        theTags = ""
        for tag in instance.tags:
            if tag["Key"] == 'Name':
                theName = '<span class="badge bg-primary text-light">{name}</span>'.format(name=tag["Value"])
            elif tag["Key"] == 'Owner':
                theOwner = '<span class="badge bg-primary text-light">{name}</span>'.format(name=tag["Value"])
            elif tag["Key"] == 'Usage':
                theUsage = '<span class="badge bg-primary text-light">{name}</span>'.format(name=tag["Value"])
            else:
                #theTags += '<span class="small">{Key}: {Value}</span><br/>'.format(Key=tag["Key"], Value=tag["Value"])
                theTags += '<span class="badge bg-info text-dark">{Key}: {Value}</span> '.format(Key=tag["Key"], Value=tag["Value"])
        theUrl = 'https://{region}.console.aws.amazon.com/ec2/v2/home?region={region}#InstanceDetails:instanceId={id}'.format(region=region_name, id=instance.id)
        theEventHistory = 'https://{region}.console.aws.amazon.com/cloudtrail/home?region={region}#/events?ResourceName={id}'.format(region=region_name, id=instance.id)

        ec2Rows += '<tr>\n'
        ec2Rows += '<td class="text-nowrap"><a href="{url}" target="_blank"><span class="iconify" data-icon="logos:aws-ec2" data-width="16" data-height="16"></span>&nbsp;{id}</a></td>\n'.format(id=instance.id, url=theUrl)
        ec2Rows += '<td><a href="{url}" target="_blank"><i class="bi bi-journal-text"></i></a></td>'.format(url=theEventHistory)
        ec2Rows += '<td>{name}</td>\n'.format(name=theName)
        ec2Rows += '<td>{region}</td>\n'.format(region=region_name)
        ec2Rows += '<td>{type}</td>\n'.format(type=instance.instance_type)

        if instance.state["Code"]==16:
            ec2Rows += '<td class="text-nowrap"><i class="bi bi-play-btn" data-toggle="tooltip" data-placement="top" title="{state}">&nbsp;{state}</i></td>\n'.format(state=instance.state["Name"])
        elif instance.state["Code"]==80:
            ec2Rows += '<td class="text-nowrap"><i class="bi bi-stop-btn" data-toggle="tooltip" data-placement="top" title="{state}">&nbsp;{state}</i></td>\n'.format(state=instance.state["Name"])
        else:
            ec2Rows += '<td class="text-nowrap">{state}</td>\n'.format(state=instance.state["Name"])

        # Details
        ec2Rows += '<td>{arch}</td>\n'.format(arch=instance.architecture)
        # Owner
        ec2Rows += '<td class="text-nowrap">{owner}</td>\n'.format(owner=theOwner)
        # usage
        ec2Rows += '<td class="text-nowrap">{usage}</td>\n'.format(usage=theUsage)

        # Tags
        ec2Rows += '<td>{tags}</td>\n'.format(tags=theTags)

        ec2Rows += '</tr>\n'
    return ec2Rows


def getRDSrows(region_name):

    rdsRows = ""

    rds = boto3.client('rds', region_name=region_name)
    paginator = rds.get_paginator('describe_db_instances').paginate()
    for page in paginator:
        for db_instance in page['DBInstances']:
            #rdsRows += str(db_instance) + "<br/>" #Debug

            db_instance_name = db_instance['DBInstanceIdentifier']
            db_type = db_instance['DBInstanceClass']  #db.t3.medium
            db_storage = db_instance['AllocatedStorage']
            db_engine =  db_instance['Engine']
            db_status = db_instance['DBInstanceStatus']

            theOwner ='<span class="badge bg-warning text-dark">No Owner</span>'
            theUsage ='<span class="badge bg-warning text-dark">No Usage</span>'
            theName = db_instance_name

            # Analyszing Tags
            theTags = ""
            for tag in db_instance['TagList']:
                if tag["Key"] == 'Name':
                    theName = '<span class="badge bg-primary text-light">{name}</span>'.format(name=tag["Value"])
                elif tag["Key"] == 'Owner':
                    theOwner = '<span class="badge bg-primary text-light">{name}</span>'.format(name=tag["Value"])
                elif tag["Key"] == 'Usage':
                    theUsage = '<span class="badge bg-primary text-light">{name}</span>'.format(name=tag["Value"])
                else:
                    theTags += '<span class="badge bg-info text-dark">{Key}: {Value}</span> '.format(Key=tag["Key"], Value=tag["Value"])

            theUrl = 'https://{region}.console.aws.amazon.com/rds/home?region={region}#database:id={id};is-cluster=false'.format(region=region_name, id=db_instance_name)
            theEventHistory = 'https://{region}.console.aws.amazon.com/rds/home?region={region}#database:id={id};is-cluster=false;tab=logs-and-events'.format(region=region_name, id=db_instance_name)

            rdsRows += '<tr>\n'
            rdsRows += '<td class="text-nowrap"><a href="{url}" target="_blank"><span class="iconify" data-icon="logos:aws-rds" data-width="16" data-height="16"></span>&nbsp;{id}</a></td>\n'.format(id=theName, url=theUrl)
            rdsRows += '<td><a href="{url}" target="_blank"><i class="bi bi-journal-text"></i></a></td>'.format(url=theEventHistory)
            rdsRows += '<td><span class="badge bg-primary text-light">{name}</span></td>'.format(name=theName)
            rdsRows += '<td>{region}</td>\n'.format(region=region_name)

            rdsRows += '<td>{type}</td>\n'.format(type=db_type)
            if db_status == 'available':
                rdsRows += '<td class="text-nowrap"><i class="bi bi-play-btn" data-toggle="tooltip" data-placement="top" title="{state}">&nbsp;{state}</i></td>\n'.format(state=db_status)
            elif db_status == 'stopped':
                rdsRows += '<td class="text-nowrap"><i class="bi bi-stop-btn" data-toggle="tooltip" data-placement="top" title="{state}">&nbsp;{state}</i></td>\n'.format(state=db_status)
            else:
                rdsRows += '<td class="text-nowrap">{state}</td>\n'.format(state=db_status)
            # Details
            rdsRows += '<td>{engine}</td>\n'.format(engine=db_engine)
            # Owner
            rdsRows += '<td class="text-nowrap">{owner}</td>\n'.format(owner=theOwner)
            # usage
            rdsRows += '<td class="text-nowrap">{usage}</td>\n'.format(usage=theUsage)
            # Tags
            rdsRows += '<td>{tags}</td>\n'.format(tags=theTags)

            rdsRows += '</tr>\n'
    return rdsRows

def lambda_handler(event, context):

    client = boto3.client('sts')
    theAccount = client.get_caller_identity()['Account']

    theList = '<table class="table table-hover table-sm small">'
    theList += '''
      <thead>
        <tr>
          <th>ID</th>
          <th>Events</th>
          <th>Name <i class="bi bi-info-circle" title='From "Name" Tag'></i></th>
          <th>Region</th>
          <th>Type</th>
          <th>State</th>
          <th>Details</th>
          <th>Owner <i class="bi bi-info-circle" title='From "Owner" Tag'></i></th>
          <th>Usage <i class="bi bi-info-circle" title='From "Usage" Tag'></i></th>
          <th>Tags</th>
        </tr>
      </thead>
      <tbody id="myTable" >
    '''


    #############################################
    ## Get region details and start async calls
    #############################################

    # Get list of ECS regions
    ec2_client = boto3.client('ec2')
    ec2_regions = [region['RegionName']
        for region in ec2_client.describe_regions()['Regions']]

    # Get list of RDS regions
    rds_regions = boto3.Session().get_available_regions('rds')


    with ThreadPoolExecutor(max_workers=20) as executor:
        future_ec2 = {executor.submit(getEC2rows, region_name): region_name for region_name in ec2_regions}
        future_rds = {executor.submit(getRDSrows, region_name): region_name for region_name in rds_regions}


    for future in as_completed(future_ec2):
        #theEc2Row = future_ec2[future]
        try:
            theList += future.result()
        except Exception as exc:
            theList += '<!-- exception: {ex} -->'.format(ex=exc)

    for future in as_completed(future_rds):
        #theRdsRow = future_rds[future]
        try:
            theList += future.result()
        except Exception as exc:
            theList += '<!-- exception: {ex} -->'.format(ex=exc)

    theList += '''
      </tbody>
    </table>
    '''

    theBody = '''\
    <!doctype html>
    <html lang="en">
    <head>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <!-- Bootstrap CSS -->
    <!-- CSS only -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.1/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-F3w7mX95PdgyTmZZMECAngseQB83DfGTowi0iMjiWaeVhAn4FJkqJByhZMI3AhiU" crossorigin="anonymous">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.5.0/font/bootstrap-icons.css">
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <script src="https://code.iconify.design/2/2.0.3/iconify.min.js"></script>

    <title>AWS Usage Report</title>
  </head>
  <body>
    <div class="container">
      <h1><span class="iconify" data-icon="logos:aws"></span> Usage Report</h1>
      <p>Below are the resources found in account {account}</p>
      <input class="form-control" id="myInput" type="text" placeholder="Search...">

    <br/>
    {theList}
    </div>
    <script>
    $(document).ready(function(){{
      $("#myInput").on("keyup", function() {{
        var value = $(this).val().toLowerCase();
        $("#myTable tr").filter(function() {{
          $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
        }});
      }});
    }});
    </script>
    <!-- JavaScript Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.1/dist/js/bootstrap.bundle.min.js" integrity="sha384-/bQdsTh/da6pkI1MST/rWKFNjaCP5gBSY4sEBT38Q/9RBh9AH40zEOg7Hlq2THRZ" crossorigin="anonymous"></script>
      </body>
</html>\
    '''.format(theList=theList, account=theAccount)

    return {
        "statusCode": 200,
        "headers": {
            'Content-Type': 'text/html'
        },
        "body": theBody
    }
