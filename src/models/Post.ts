/* eslint-disable prettier/prettier */
import mongoose, { Document, PopulatedDoc, Schema } from 'mongoose';

import TextService from '../services/TextService';
import { Model } from '../utils/constants';
import { BaseModel, ID } from '../utils/types';
import { CommentDocument } from './Comment';
import { ReactionDocument } from './Reaction';
import User, { UserDocument } from './User';

export enum PostType {
  HELP = 'HELP', // Asking for help...
  TIL = 'TIL', // Today I learned...
  WIN = 'WIN' // Sharing a win...
}

/**
 * TODO: (3.02)
 * - Read this interface.
 * - Delete this comment once you've done so.
 */
interface IPost extends BaseModel {
  /**
   * User that is associated with the creation of the post.
   */
  author: PopulatedDoc<UserDocument>;

  /**
   * List of comments that were created on the post.
   */
  comments: PopulatedDoc<CommentDocument>[];

  /**
   * Text content of the post.
   */
  content: string;

  /**
   * List of reactions that were created on the reaction.
   */
  reactions: PopulatedDoc<ReactionDocument>[];

  /**
   * Type of the post that was created. This can be null, if no PostType
   * if specified.
   */
  type?: PostType; // ? means optional.
}

export type PostDocument = Document<{}, {}, IPost> & IPost;

const postSchema: Schema<PostDocument> = new Schema<PostDocument>(
  {
    author: { ref: Model.USER, required: true, type: ID }, // author will be referenced by USER model, it is required and it's type is an ID
    content: { required: true, type: String }, // content is required and it will be a string
    type: { required: false, type: String } // type is not required, and would be a string
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
  }
);

const sendNotification = async function (
  author: PopulatedDoc<UserDocument, {} & string>
) {
  const allUsers: UserDocument[] = await User.find(); // type of user variable will be an array of user documents (UserDocument[]) and in order to populate the array must call an await function called User.find() (Mongoose command)

  // eslint-disable-next-line array-callback-return
  allUsers.map((user) => {
    // called .map so that this code gets used for every item in the array of allUsers
    if (user !== author) {
      // if statement to ensure that the user we are sending notification to, is not the author of the post
      TextService.sendText({
        message: 'One of your podmates shared an update!',
        to: user.phoneNumber
      });
    }
  });
};

postSchema.pre('save', function () {
  if (this.isNew) {
    sendNotification(this.author);
  }
});

// Creates a "virtual" property on the Post model called 'comments'. By
// default, this sorts comments by the createdAt in ascending order (AKA we
// want to see newer comments last).
postSchema.virtual('comments', {
  foreignField: 'post',
  localField: '_id',
  options: { sort: { createdAt: 1 } },
  ref: Model.COMMENT
});

// Similar to above, creates a "virtual" property called 'reactions' and we
// want to sort these in ascending order by their creation date/time.
postSchema.virtual('reactions', {
  foreignField: 'post',
  localField: '_id',
  options: { sort: { createdAt: 1 } },
  ref: Model.REACTION
});

const Post: mongoose.Model<PostDocument> = mongoose.model<PostDocument>(
  Model.POST,
  postSchema
);

export default Post;
