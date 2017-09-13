
var crypto = require('crypto');
var mongodb = require('mongodb');
var Binary = require('mongodb').Binary;
var userColl = undefined;
var saltLengthBytes = 64;
var hashIterations = 10000;
var keyLengthBytes = 64;

function authenticateUser(id, password, callback)
{
	try
	{
		readUser(id, function(result) {
			if (result instanceof Error)
			{
				console(result.message);
				if (callback)
					callback(result);
			}
			else
			{
				if (result)
				{
					crypto.pbkdf2(password, result.salt.read(0, result.salt.length()), hashIterations, keyLengthBytes, function(err, key){
						if (err)
						{
							console.log(err.message);
							if (callback)
								callback(err);
						}
						else
						{
							var derivedKey = new Binary(key);
							if (callback)
						    	callback(derivedKey.value() === result.password.value());
						}
					});
				}
				else
				{
					callback(false);
				}
			}
		});
	}
	catch (exc)
	{
		console.log(exc.message);
		if (callback)
			callback(exc);
	}
};

function createUser(doc, callback)
{
	try
	{
		crypto.randomBytes(saltLengthBytes, function(err1, buf) {  //create the salt for the hash function
			if (err1)
			{
				console.log(err1.message);
				if (callback)
					callback(err1);
			}
			else
			{
				doc.salt = new Binary(buf);  //put salt result in a mongodb Binary object
				
				//Invoke hash function with salt object
				crypto.pbkdf2(doc.password, doc.salt.read(0, doc.salt.length()), hashIterations, keyLengthBytes, function(err2, key){ 
					if (err2)
					{
						console.log(err2.message);
						if (callback)
							callback(err2);
					}
					else
					{
						doc.password = new Binary(key);
						if (userColl)
						{
							userColl.insert(doc, function(err3, result) {  //insert user into DB
								if (err3)
								{
									console.log(err3.message);
									if (callback)
										callback(err3);
								}
								else
								{
									if (callback)
										callback(result);
								}
							});
						}
						else
						{
							var err4 = new Error('Database not initialized');
							console.log(err4.message);
							callback(err4);
						}
					}
				});
			}
		});
	}
	catch (exc)
	{
		console.log(exc.message);
		if (callback)
			callback(exc);
	}
};

function deleteUser(id, callback)
{
	try
	{
		if (userColl)
		{
			userColl.remove({_id : id}, function(err, result) {
				if (err)
				{
					console.log(err.message);
					if (callback)
						callback(err);
				}
				else
				{
					if (callback)
						callback(result);
				}
			});
		}
		else
		{
			var err = new Error('Database not initialized');
			console.log(err.message);
			callback(err);
		}
	}
	catch (exc)
	{
		console.log(exc.message);
		if (callback)
			callback(exc);
	}
};

function readUser(id, callback)
{
	try
	{
		if (userColl)
		{
			userColl.findOne({_id : id}, function(err, result) {
				if (err)
				{
					console.log(err.message);
					if (callback)
						callback(err);
				}
				else
				{
					if (callback)
						callback(result);
				}
			});
		}
		else
		{
			var err = new Error('Database not initialized');
			console.log(err.message);
			callback(err);
		}
	}
	catch (exc)
	{
		console.log(exc.message);
		if (callback)
			callback(exc);
	}
};

mongodb.MongoClient.connect('mongodb://localhost:27017/recipeboks', function(err, db){
	if (!err && db)
	{
		userColl = db.collection('users');
		createUser({_id : 1000, name : 'user1000', password : 'userPa$$word'}, function(result1){
			if (!(result1 instanceof Error))
			{
				console.log('Authenticating valid user name (1000) and password (userPa$$word)')
				authenticateUser(1000, 'userPa$$word', function(result2){
					if (!(result2 instanceof Error) && result2 == true)
						console.log('Results: User authenticated');
					else
						console.log('Results: User name or password does not match');
				
					console.log('\n'+ 'Authenticating invalid user name (1111)')
					authenticateUser(1111, 'userPa$$word', function(result3){
						if (!(result3 instanceof Error) && result3 == true)
							console.log('Results: User authenticated');
						else
							console.log('Results: User name or password does not match');
				
						console.log('\n' + 'Authenticating valid user name (1000) but invalid password (userPassword)')
						authenticateUser(1000, 'userPassword', function(result4){
							if (!(result4 instanceof Error) && result4 == true)
								console.log('Results: User authenticated');
							else
								console.log('Results: User name or password does not match');
							deleteUser(1000, function(result5){ 
								db.close();
							});	
						});
					});
				});	
			}
		});
	}
});
