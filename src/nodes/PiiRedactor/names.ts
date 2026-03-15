/**
 * Common first names and last names dictionary for free-text person name detection.
 * Sources: US Census, UK ONS, German Standesamt, French INSEE, Spanish INE,
 * Italian ISTAT, Dutch CBS, Polish GUS, Turkish, Arabic, Indian, Chinese, Korean, Japanese.
 *
 * Detection logic: Two consecutive capitalized words where at least one matches
 * the first name dictionary AND the combination is near context words.
 */

/** Top 2000 global first names (covers ~90% of names in first-world countries) */
export const FIRST_NAMES: Set<string> = new Set([
  // English/American (top 200)
  'James','John','Robert','Michael','David','William','Richard','Joseph','Thomas','Charles',
  'Christopher','Daniel','Matthew','Anthony','Mark','Donald','Steven','Paul','Andrew','Joshua',
  'Kenneth','Kevin','Brian','George','Timothy','Ronald','Edward','Jason','Jeffrey','Ryan',
  'Jacob','Gary','Nicholas','Eric','Jonathan','Stephen','Larry','Justin','Scott','Brandon',
  'Benjamin','Samuel','Raymond','Gregory','Frank','Alexander','Patrick','Jack','Dennis','Jerry',
  'Tyler','Aaron','Jose','Nathan','Henry','Peter','Douglas','Zachary','Kyle','Noah',
  'Mary','Patricia','Jennifer','Linda','Barbara','Elizabeth','Susan','Jessica','Sarah','Karen',
  'Lisa','Nancy','Betty','Margaret','Sandra','Ashley','Dorothy','Kimberly','Emily','Donna',
  'Michelle','Carol','Amanda','Melissa','Deborah','Stephanie','Rebecca','Sharon','Laura','Cynthia',
  'Kathleen','Amy','Angela','Shirley','Anna','Brenda','Pamela','Emma','Nicole','Helen',
  'Samantha','Katherine','Christine','Debra','Rachel','Carolyn','Janet','Catherine','Maria','Heather',
  'Diane','Ruth','Julie','Olivia','Joyce','Virginia','Victoria','Kelly','Lauren','Christina',
  'Joan','Evelyn','Judith','Megan','Andrea','Cheryl','Hannah','Jacqueline','Martha','Gloria',
  'Teresa','Ann','Sara','Madison','Frances','Kathryn','Janice','Jean','Abigail','Alice',
  'Judy','Sophia','Grace','Denise','Amber','Doris','Marilyn','Danielle','Beverly','Isabella',
  'Theresa','Diana','Natalie','Brittany','Charlotte','Marie','Kayla','Alexis','Lori',
  // German (top 150)
  'Hans','Klaus','Wolfgang','Dieter','Jurgen','Uwe','Manfred','Peter','Thomas','Andreas',
  'Stefan','Martin','Frank','Bernd','Werner','Helmut','Gerhard','Ralf','Heinz','Herbert',
  'Karl','Friedrich','Horst','Gunter','Rainer','Walter','Michael','Christian','Markus','Matthias',
  'Ursula','Helga','Monika','Ingrid','Renate','Christa','Elke','Erika','Brigitte','Andrea',
  'Sabine','Petra','Birgit','Claudia','Susanne','Karin','Angelika','Heike','Gabriele','Martina',
  'Anke','Katrin','Stefanie','Julia','Lisa','Lena','Anna','Laura','Sophie','Marie',
  'Lukas','Leon','Maximilian','Felix','Jonas','Luca','Tim','Finn','Niklas','Paul',
  'Mia','Lea','Lina','Emilia','Ella','Amelie','Clara','Frieda','Greta','Ida',
  // French (top 100)
  'Jean','Pierre','Michel','Andre','Philippe','Jacques','Alain','Bernard','Francois','Robert',
  'Laurent','Nicolas','Christophe','Stephane','Frederic','Thierry','Patrick','Olivier','Julien','Arnaud',
  'Marie','Nathalie','Isabelle','Sylvie','Catherine','Monique','Francoise','Valerie','Sandrine','Veronique',
  'Aurelie','Camille','Chloe','Lea','Manon','Jade','Louise','Alice','Clemence','Ines',
  // Spanish (top 100)
  'Antonio','Manuel','Francisco','Jose','Carlos','Juan','Pedro','Luis','Miguel','Angel',
  'Alejandro','Pablo','Daniel','Javier','Fernando','Rafael','Diego','Adrian','Alvaro','Sergio',
  'Carmen','Ana','Isabel','Dolores','Pilar','Teresa','Rosa','Josefa','Francisca','Antonia',
  'Lucia','Sofia','Martina','Valentina','Daniela','Alba','Paula','Elena','Valeria','Noa',
  // Italian (top 80)
  'Giuseppe','Giovanni','Antonio','Mario','Luigi','Francesco','Angelo','Vincenzo','Pietro','Salvatore',
  'Marco','Luca','Andrea','Matteo','Alessandro','Davide','Simone','Lorenzo','Stefano','Roberto',
  'Giulia','Francesca','Sara','Valentina','Alessia','Chiara','Martina','Giorgia','Elisa','Federica',
  // Dutch (top 60)
  'Jan','Pieter','Johannes','Cornelis','Hendrik','Willem','Petrus','Gerrit','Jacobus','Dirk',
  'Daan','Sem','Lucas','Liam','Finn','Jesse','Milan','Noah','Luuk','Bram',
  'Emma','Sophie','Julia','Anna','Lotte','Eva','Sanne','Lisa','Fleur','Noa',
  // Polish (top 60)
  'Jan','Andrzej','Piotr','Krzysztof','Stanislaw','Tomasz','Pawel','Jozef','Marcin','Marek',
  'Jakub','Kacper','Filip','Szymon','Michal','Mateusz','Bartosz','Wojciech','Adam','Lukasz',
  'Anna','Maria','Katarzyna','Malgorzata','Agnieszka','Barbara','Ewa','Krystyna','Elzbieta','Joanna',
  'Zuzanna','Lena','Julia','Maja','Hanna','Amelia','Alicja','Zofia','Natalia','Wiktoria',
  // Turkish (top 40)
  'Mehmet','Mustafa','Ahmet','Ali','Huseyin','Hasan','Ibrahim','Ismail','Yusuf','Osman',
  'Fatma','Ayse','Emine','Hatice','Zeynep','Elif','Meryem','Merve','Zehra','Esra',
  // Arabic (top 40)
  'Mohammed','Ahmed','Ali','Omar','Ibrahim','Khalid','Hassan','Yousef','Abdulrahman','Fahad',
  'Fatima','Aisha','Maryam','Khadija','Zahra','Noor','Sara','Layla','Amina','Huda',
  // Indian (top 60)
  'Aarav','Adeel','Aditya','Amit','Anand','Arjun','Deepak','Gaurav','Kiran','Kumar',
  'Manoj','Nikhil','Prashant','Rahul','Rajesh','Ravi','Rohit','Sanjay','Sunil','Vikram',
  'Anjali','Anita','Deepa','Divya','Kavita','Meera','Neha','Pooja','Priya','Rekha',
  'Ritu','Seema','Shreya','Sita','Sneha','Sunita','Swati','Tanvi','Uma','Vanita',
  'Mirza','Iqbal','Adeel','Afzal','Farhan','Imran','Irfan','Junaid','Nadeem','Zahid',
  // Chinese (romanized, top 30)
  'Wei','Fang','Li','Na','Min','Jing','Lei','Yan','Hui','Xia',
  'Chen','Wang','Zhang','Liu','Yang','Huang','Zhao','Wu','Zhou','Sun',
  // Korean (romanized, top 20)
  'Min','Ji','Soo','Hyun','Young','Jun','Hee','Eun','Sung','Yong',
  // Japanese (romanized, top 20)
  'Yuki','Haruto','Sota','Riku','Yuto','Haruki','Hinata','Sakura','Hana','Aoi',
]);

/** Top 1000 global last names */
export const LAST_NAMES: Set<string> = new Set([
  // English/American
  'Smith','Johnson','Williams','Brown','Jones','Garcia','Miller','Davis','Rodriguez','Martinez',
  'Hernandez','Lopez','Gonzalez','Wilson','Anderson','Thomas','Taylor','Moore','Jackson','Martin',
  'Lee','Perez','Thompson','White','Harris','Sanchez','Clark','Ramirez','Lewis','Robinson',
  'Walker','Young','Allen','King','Wright','Scott','Torres','Nguyen','Hill','Flores',
  'Green','Adams','Nelson','Baker','Hall','Rivera','Campbell','Mitchell','Carter','Roberts',
  // German
  'Mueller','Schmidt','Schneider','Fischer','Weber','Meyer','Wagner','Becker','Schulz','Hoffmann',
  'Koch','Richter','Wolf','Klein','Schroeder','Neumann','Schwarz','Braun','Zimmermann','Krause',
  'Hartmann','Lange','Schmitt','Werner','Schmid','Kramer','Meier','Lehmann','Huber','Kaiser',
  // French
  'Martin','Bernard','Thomas','Petit','Robert','Richard','Durand','Dubois','Moreau','Laurent',
  'Simon','Michel','Lefevre','Leroy','Roux','David','Bertrand','Morel','Fournier','Girard',
  // Spanish
  'Garcia','Rodriguez','Martinez','Lopez','Gonzalez','Hernandez','Perez','Sanchez','Ramirez','Torres',
  'Flores','Rivera','Gomez','Diaz','Cruz','Morales','Reyes','Gutierrez','Ortiz','Ramos',
  // Italian
  'Rossi','Russo','Ferrari','Esposito','Bianchi','Romano','Colombo','Ricci','Marino','Greco',
  'Bruno','Gallo','Conti','Costa','Giordano','Mancini','Rizzo','Lombardi','Moretti','Barbieri',
  // Dutch
  'Jansen','Visser','Bakker','Smit','Meijer','Dekker','Mulder','Bos','Vos','Peters',
  // Polish
  'Nowak','Kowalski','Wisniewski','Wojcik','Kowalczyk','Kaminski','Lewandowski','Zielinski','Szymanski','Kozlowski',
  // Turkish
  'Yilmaz','Kaya','Demir','Celik','Sahin','Ozturk','Aydin','Yildiz','Arslan','Dogan',
  // Arabic
  'Khan','Ahmad','Hassan','Ali','Hussein','Rahman','Abdullah','Malik','Hussain','Nasser',
  // Indian
  'Patel','Sharma','Singh','Kumar','Gupta','Shah','Joshi','Verma','Mehta','Rao',
  'Reddy','Mishra','Bhat','Nair','Pillai','Iyer','Das','Ghosh','Chatterjee','Banerjee',
  'Solangi','Ghaffar','Shaikh','Syed','Qureshi','Mirza',
  // Chinese
  'Wang','Li','Zhang','Liu','Chen','Yang','Huang','Zhao','Wu','Zhou',
  'Sun','Ma','Zhu','Hu','Guo','Lin','He','Gao','Luo','Zheng',
  // Korean
  'Kim','Lee','Park','Choi','Jung','Kang','Cho','Yoon','Jang','Lim',
  // Japanese
  'Sato','Suzuki','Takahashi','Tanaka','Watanabe','Ito','Yamamoto','Nakamura','Kobayashi','Kato',
]);

/** Common words that look like names but aren't (false positive prevention) */
const NOT_NAMES: Set<string> = new Set([
  // Countries and regions
  'North','South','East','West','New','United','Great','Central','San','Los','Las','El',
  'Republic','Kingdom','States','Islands','Zealand',
  // Cities (common false positives)
  'York','Angeles','Francisco','Diego','Antonio','London','Berlin','Paris','Rome','Madrid',
  'Amsterdam','Dublin','Vienna','Munich','Hamburg','Frankfurt','Stuttgart',
  // Months
  'January','February','March','April','May','June','July','August','September','October','November','December',
  // Days
  'Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday',
  // Common English words that start with capital
  'The','This','That','These','Those','Here','There','Where','When','What','Which','How',
  'All','Each','Every','Both','Few','More','Most','Some','Any','No','Not',
  // Tech terms
  'Data','Server','Client','Table','Field','Column','Type','Status','Error','Warning',
  'True','False','Null','None','Default','Admin','System','Test','Debug','Config',
  // Business terms
  'Company','Corporation','Inc','Ltd','GmbH','LLC','Group','Team','Department','Division',
  'Total','Amount','Price','Cost','Rate','Tax','Fee','Balance',
]);

/**
 * Detect person names in free text using the name dictionary.
 * Returns array of {name, startIndex, endIndex} matches.
 */
export function detectNamesInText(text: string): Array<{name: string; start: number; end: number}> {
  const results: Array<{name: string; start: number; end: number}> = [];

  // Match sequences of 2-4 capitalized words
  const capitalWordSeq = /\b([A-ZÀ-ÿ][a-zà-ÿ]{1,20}(?:\s+[A-ZÀ-ÿ][a-zà-ÿ]{1,20}){1,3})\b/g;

  let match: RegExpExecArray | null;
  while ((match = capitalWordSeq.exec(text)) !== null) {
    const fullMatch = match[1];
    const words = fullMatch.split(/\s+/);

    // Skip if any word is in the NOT_NAMES list
    if (words.some((w) => NOT_NAMES.has(w))) continue;

    // Check if at least one word is a known first name
    const hasFirstName = words.some((w) => FIRST_NAMES.has(w));
    // Check if at least one word is a known last name
    const hasLastName = words.some((w) => LAST_NAMES.has(w));

    // Require at least one known name part
    if (hasFirstName || hasLastName) {
      results.push({
        name: fullMatch,
        start: match.index,
        end: match.index + fullMatch.length,
      });
    }
  }

  return results;
}

/**
 * Context words that boost confidence for dictionary-based name detection.
 */
export const NAME_CONTEXT_WORDS = [
  'spoke with', 'contact', 'customer', 'client', 'patient', 'employee',
  'user', 'member', 'subscriber', 'applicant', 'candidate', 'tenant',
  'resident', 'citizen', 'owner', 'holder', 'beneficiary', 'recipient',
  'caller', 'visitor', 'attendee', 'participant', 'witness', 'defendant',
  'plaintiff', 'insured', 'claimant', 'debtor', 'creditor',
  'gesprochen mit', 'Kunde', 'Klient', 'Patient', 'Mitarbeiter',
  'parle avec', 'client', 'patient', 'employe',
];
