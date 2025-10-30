> permissions_db and findex are both findex_arc. Do you really need to pass it twice? If not, then maybe can you internalize the Arc in PermissionDb::new by taking ownership of Findex.

This "findex_arc" naming is useless I guess since it adds just more confusion, I will change it to `findex` simply

As of why it is in both at the same time, it's needed because findex can be either called :
1. While adding new permissions
2. When an object is created and its data needs to be indexed

that's why I didn't internalize it, I hope I understood what you meant

> Review you naming:

done

> This should be an error case if the DB is not set to use Findex v8. Keep the option in your migration parameters or perform the DB check here.

I am not sure to follow, why is this an error  (let's discuss this on the team's messagery)

> Either your naming is confusing, either this is the wrong key.

My naming is confusing I guess, I changed it to "master key". Also I will do more cleaning of that legacy code since most of it turned out useless

UPDATE : I deleted **A lot** of copy pasted useless legacy code. When I created this module I didn't know what's safely deletable and what's not but now I am sure that almost all of that structure (except the permissions part) was actually useless


> I see no collision in this file. Please import the Serializer, same for the others.

Fixed

> You should now be able to write a simpler version of this serialization since I have implemented the Serializable for String.
and
> You might have wanted to implement Serializable for KmipOperation instead of using the representation as it would have allowed to write:

As to my understand, the suggestion is implementing seizable for the structs components one by one to use them directly here, correct ? I am not against that but won't that create x 3 implementations instead of originally just this one ? (so 3 times more code)

I think I might have not understood very well, let's talk about this too before I submit my review fixes
