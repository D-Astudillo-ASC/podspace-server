/* eslint-disable prettier/prettier */
import mongoose, { Document, PopulatedDoc, Schema } from 'mongoose';

import TextService from '../services/TextService';
import { Model } from '../utils/constants';
import { BaseModel, ID } from '../utils/types';
import Post, { PostDocument } from './Post';
import User, { UserDocument } from './User';

/**
 * TODO: (5.01)
 * - Read this interface.
 * - Delete this comment once you've done so.
 */
interface IComment extends BaseModel {
  /**
   * User that is associated with the creation of the comment.
   */
  author: PopulatedDoc<UserDocument>;

  /**
   * Text content of the comment.
   */
  content: string;

  /**
   * Post that the comment was created on.
   */
  post: PopulatedDoc<PostDocument>;
}

export type CommentDocument = Document<{}, {}, IComment> & IComment;

const commentSchema: Schema<CommentDocument> = new Schema<CommentDocument>(
  {
    /**
     * (5.02) TODO:
     * - Create the schema for the Comments that we'll save in the database using
     * the interface above as a reference.
     * - Delete this comment and the example field.
     * - Add comment(s) to explain your work.
     */
    author: { ref: Model.USER, required: true, type: ID },
    content: { required: true, type: String },
    post: { ref: Model.POST, required: true, type: ID }
  },
  { timestamps: true }
);

commentSchema.pre('save', async function () {
  if (this.isNew) {
    const post: PostDocument = await Post.findById(this.post);
    const postAuthor: UserDocument = await User.findById(post.author);

    TextService.sendText({
      message: 'One of your podmates commented on your post!',
      to: postAuthor.phoneNumber
    });
  }
});

const Comment: mongoose.Model<CommentDocument> =
  mongoose.model<CommentDocument>(Model.COMMENT, commentSchema);

export default Comment;
