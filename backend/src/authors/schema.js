import mongoose from "mongoose";
import bCrypt from "bcrypt";

const authorSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    surname: { type: String, required: true },
    email: { type: String, required: true },
    dateOfBirth: { type: Date, required: true },
    avatar: {
      type: String,
      default: "https://ui-avatars.com/api/?name=Unnamed+User",
    },
  },
  { timestamps: true }
);

const hashPassword = async obj => {
    let plainPassword = obj.password
    let isChanged = obj.isModified( 'password' )
    if (isChanged)
        obj.password = await bCrypt.hash(plainPassword, 10);
}

const getAvatarUrl = obj => this.avatar = `https://ui-avatars.com/api/?name=${this.name}+${this.surname}`

authorSchema.pre("save", async function (done) {
    await hashPassword( this )
    getAvatarUrl(this)
    done();
});

authorSchema.statics.checkPassword = async function( email, psw ) {
    let authorObj = await this.findOne({ email: email})
    const exist = !!authorObj
    if (exist) {
        const isCorrect = await bCrypt.compare(psw, authorObj.password)
        if(isCorrect) return authorObj; else return null
    } else return null

}


authorSchema.methods.toJSON = function () {
    let authorResponseObj = this.toObject()
    delete authorResponseObj.password
    delete authorResponseObj.__v
    return authorResponseObj
}

export default mongoose.model("Author", authorSchema);
