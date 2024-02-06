import yaml
from stix2 import Bundle, Campaign, AttackPattern, ExtensionDefinition, Identity, Relationship, IPv4Address, URL, DomainName, UserAccount, Artifact, Directory, exceptions, NetworkTraffic, EmailAddress

                  
# Funzione per capire il tipo di input richiesto
def tipo_input(valore):
    if "IP" in valore:
        return "ipv4-addr"
    elif "hash" in valore:
        return "artifact"
    elif "user" in valore or "User" in valore or "Hostname" in valore or "hostname" in valore or "Password" in valore or "password" in valore:
        return "user-account"
    elif "url" in valore or "URL" in valore or "download" in valore:
        return "url"
    elif "domain" in valore or "Domain" in valore:
        return "domain-name"
    elif "port" in valore or "Port" in valore:
        return "network_traffic"
    elif "Path" in valore or "path" in valore:
        return "directory"   
    elif "email" in valore:
        return "email-address"         

    


# Lettura del file YAML descrivente l'APT
with open(".../Percorso_dell'apt/.../Emulation_Plan/yaml/Nome_del_file.yaml", "r") as file_yaml:
    apt = yaml.safe_load(file_yaml)


# Creazione di oggetti Identity ed Extension Definition per ampliare la definizione dell'oggetto Attack Pattern
io = Identity(
    name = "Francesco Avallone",
    identity_class = "individual"
)

extension = ExtensionDefinition(
            schema = "hhttps://github.com/FranAva001/Analisi_Delle_APT/blob/main/Extension%20Definition/Extension_Definition.json",
            extension_types = "property-extension",
            type = "extension-definition",
            name = "Extension Definition",
            description = "Oggetto di tipo Extension Definition per estendere la definizione dell'Attack Pattern",
            created_by_ref = io.get('id'),
            version = "2.1",
            )

# Vettore che sarà riempito con gli oggetti della nostra rappresentazione STIX
oggetti_stix = []

# Variabile utilizzata per capire quando ci troviamo alla prima iterazione del ciclo, dato che il primo dizionario del file YAML rappresenta l'adversary
prima_volta = True

# Ciclo per analizzare tutti i dizionari del file YAML per popolare il nostro file STIX
for ability in apt:
    if prima_volta:
        campaign_details = ability.get('emulation_plan_details', {})
        campaign = Campaign(
            id = "campaign--" + campaign_details.get('id'),
            name = campaign_details.get('adversary_name'),
            description = campaign_details.get('adversary_description')
        )
        prima_volta = False
        oggetti_stix.append(campaign)

    else:
        attackpattern = AttackPattern(
            id =  "attack-pattern--" + ability.get('id'),
            name = ability.get('name'),
            description = ability.get('description'),
            extensions = {
                extension.id : {
                    "technique_name" : ability.get('technique', {}).get('name'),
                    "attack_id" : ability.get('technique', {}).get('attack_id'),
                    "input_arguments" : ability.get('input_arguments'),
                    "platforms" : ability.get('platforms', {})
                }
            }
           
        )
        
        oggetti_stix.append(attackpattern)
        for nome_input, valore_input in ability.get('input_arguments', {}).items():
            # In base al tipo di input, creeremo un oggetto specifico per rappresentare l'input del corrispondente comando
            if valore_input.get('default'):
                if tipo_input(valore_input.get('description')) == "ipv4-addr":
                    input = IPv4Address(
                            value = valore_input.get('default')
                    )
                    localhost = input
                    
                elif tipo_input(valore_input.get('description')) == "url":
                    input = URL(
                            value = valore_input.get('default')
                    )

                elif tipo_input(valore_input.get('description')) == "domain-name":
                    input = DomainName(
                            value = valore_input.get('default')
                    )

                elif tipo_input(valore_input.get('description')) == "user-account":
                    if isinstance(valore_input.get('default'), int):
                        input = UserAccount(
                                user_id = str(valore_input.get('default'))
                        )
                    else:
                        input = UserAccount(
                                account_login = valore_input.get('default')
                        )
                    if "Password" in valore_input.get('description') or "password" in valore_input.get('description'):
                        input = UserAccount(
                                credential = valore_input.get('default')
                        )

                elif tipo_input(valore_input.get('description')) == "artifact":
                    try:
                        input = Artifact(
                            hashes = {"MD5" : valore_input.get('default')},
                            url = ""
                        )
                       
                    except exceptions.InvalidValueError:
                        if valore_input.get('default'):
                            input = Artifact(
                                hashes = {"MD5" : valore_input.get('default').split(":")[0]},
                                url = ""
                            )
                         
                        else: 
                            pass

                elif tipo_input(valore_input.get('description')) == "network_traffic":
                    input = NetworkTraffic(
                        dst_port = valore_input.get('default'),
                        protocols = "",
                        src_ref = localhost.id
                    )
                   
                elif tipo_input(valore_input.get('description')) == "directory":
                    try:
                        input = Directory(
                            path = valore_input.get('default')
                        )
                        
                    except exceptions.MissingPropertiesError:
                        input = Directory(
                            path = ""
                        )
                        
                elif tipo_input(valore_input.get('description')) == "email-address":
                    input = EmailAddress(
                        value = valore_input.get('default')
                    )
                   
                else:
                    print("Nessun oggetto a disposizione per rappresentare l'input")
                    input = None
            # Creazione di un oggetto Relationship per collegare l'input all'ability
            if input:
               input_relationship = Relationship(source_ref=attackpattern.get('id'), target_ref=input.get('id'), relationship_type="uses")
               oggetti_stix.append(input_relationship)
               oggetti_stix.append(input)
                

        # Creazione di un ulteriore oggetto Relationship per collegare l'ability alla campagna       
        attack_relationship = Relationship(source_ref=campaign.get('id'), target_ref=attackpattern.get('id'), relationship_type="uses")
        oggetti_stix.append(attack_relationship)
        
        


# Creazione e serializzazione di un oggetto Bundle, che rappresenta il contenuto del nostro file STIX
bundle = Bundle(oggetti_stix)
contenuto_bundle = bundle.serialize(pretty = True)

# Creazione di un file STIX a partire del contenuto dell'oggetto Bundle
with open(campaign.name + ".stix", "w") as file_stix:
    file_stix.write(contenuto_bundle)

print("File STIX generato con successo!")
